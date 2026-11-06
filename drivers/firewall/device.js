'use strict';

const Homey = require('homey');
const { OPNsenseClient, PRIVILEGES } = require('../../lib/OPNsenseClient');
const h = require('../../lib/health');

const CAPABILITIES = [
  'alarm_generic', 'opn_status', 'opn_wan_online', 'opn_wan_latency', 'opn_wan_loss',
  'opn_wan_download', 'opn_wan_upload', 'opn_load', 'opn_memory', 'measure_temperature',
  'opn_disk', 'opn_states', 'opn_services_down', 'opn_if_errors', 'opn_uptime',
];
const MIN_POLL_S = 30;
const UNREACHABLE_AFTER = 2; // consecutive failed polls before "unreachable"
const BUCKET_MS = 5 * 60 * 1000; // history resolution for the widget
const HISTORY_MS = 24 * 3600 * 1000;
const ERROR_WINDOW_MS = 3600 * 1000;
const MAX_EVENTS = 25;
const PERSIST_EVERY_MS = 15 * 60 * 1000;

class FirewallDevice extends Homey.Device {
  async onInit() {
    for (const c of CAPABILITIES) {
      if (!this.hasCapability(c)) await this.addCapability(c).catch(this.error);
    }
    this.snap = null; // last parsed snapshot
    this.problems = new Map((this.getStoreValue('problems') || []).map((p) => [p.code, p]));
    this.history = this.getStoreValue('history') || []; // [t, delayMax, lossMax, rxAvg, txAvg]
    this.events = this.getStoreValue('events') || []; // [t, kind, text]
    this.errorLog = []; // [t, newErrors]
    this.failures = 0;
    this.unreachableSince = this.getStoreValue('unreachable_since') || null;
    this.wanDownSince = this.getStoreValue('wan_down_since') || null;
    this._bucket = null;
    this._persistedAt = Date.now();

    this._buildClient();
    this._schedule();
    this.homey.setTimeout(() => this.poll().catch(() => {}), 1000);
  }

  _buildClient() {
    const s = this.getStore();
    this.client = s.url ? new OPNsenseClient({ ...s, log: (...a) => this.log(...a) }) : null;
    this._prevIfaces = null;
  }

  _schedule() {
    if (this.timer) this.homey.clearInterval(this.timer);
    const sec = Math.max(MIN_POLL_S, Number(this.getSetting('poll_interval')) || 60);
    this.timer = this.homey.setInterval(() => this.poll().catch(() => {}), sec * 1000);
  }

  async updateConnection(creds) {
    for (const [k, v] of Object.entries(creds)) await this.setStoreValue(k, v);
    await this.setSettings({
      url: creds.url, fingerprint: creds.fingerprint || this.homey.__('settings.ca_verified'),
    }).catch(this.error);
    this._buildClient();
    await this.setAvailable().catch(this.error);
    this.poll().catch(() => {});
  }

  async onSettings({ changedKeys }) {
    if (changedKeys.includes('poll_interval')) this.homey.setTimeout(() => this._schedule(), 0);
    // Re-evaluate with new thresholds / filters right away.
    this.homey.setTimeout(() => this.poll().catch(() => {}), 500);
  }

  async onUninit() {
    if (this.timer) this.homey.clearInterval(this.timer);
    await this._persist().catch(() => {});
  }

  onDeleted() {
    if (this.timer) this.homey.clearInterval(this.timer);
  }

  _thresholds() {
    const s = this.getSettings();
    return {
      latencyMs: s.th_latency,
      lossPct: s.th_loss,
      temperatureC: s.th_temperature,
      memoryPct: s.th_memory,
      diskPct: s.th_disk,
      statesPct: s.th_states,
      load: s.th_load,
      errorsPerHour: s.th_errors,
    };
  }

  // ------------------------------------------------------------------ polling

  /** Coalesces overlapping polls (timer + flow "refresh" + settings change). */
  poll() {
    if (!this._polling) this._polling = this._poll().finally(() => { this._polling = null; });
    return this._polling;
  }

  async _poll() {
    if (!this.client) {
      await this.setUnavailable(this.homey.__('device.no_connection')).catch(this.error);
      return;
    }
    let result;
    try {
      result = await this.client.snapshot();
    } catch (err) {
      await this._onPollError(err);
      return;
    }
    await this._onSnapshot(result);
  }

  async _onPollError(err) {
    this.log('Poll failed:', err.message);
    await this._setSetting('last_error', `${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC — ${err.message}`);

    if (err.auth) {
      await this.setUnavailable(this.homey.__('device.auth_failed')).catch(this.error);
      return;
    }
    if (err.cert) {
      await this.setUnavailable(this.homey.__('device.cert_changed')).catch(this.error);
      return;
    }
    this.failures += 1;
    if (this.failures < UNREACHABLE_AFTER || this.unreachableSince) return;

    this.unreachableSince = Date.now();
    await this.setStoreValue('unreachable_since', this.unreachableSince).catch(this.error);
    const text = this.homey.__('problem.unreachable');
    await Promise.all([
      this._set('alarm_generic', true),
      this._set('opn_status', text),
    ]);
    this._event('unreachable', text);
    this.driver.triggers.unreachable.trigger(this, {}, {}).catch(this.error);
    this.homey.app.notifyWidgets();
  }

  async _onSnapshot({ raw, forbidden }) {
    const now = Date.now();
    this.failures = 0;
    if (!this.getAvailable()) await this.setAvailable().catch(this.error);

    if (this.unreachableSince) {
      const minutes = Math.round((now - this.unreachableSince) / 60000);
      this.unreachableSince = null;
      await this.setStoreValue('unreachable_since', null).catch(this.error);
      this._event('reachable', this.homey.__('event.reachable', { minutes }));
      this.driver.triggers.reachable.trigger(this, { minutes }, {}).catch(this.error);
    }

    const prev = this.snap;
    const s = h.parseSnapshot(raw, {
      gatewayName: this.getSetting('gateway_name'),
      wanInterface: this.getSetting('wan_interface'),
      ignoreServices: this.getSetting('ignore_services'),
    });

    // Interface counters -> throughput and error rate
    let rates = { rxMbps: null, txMbps: null, newErrors: 0 };
    if (s.interfaces) {
      if (this._prevIfaces) {
        rates = h.interfaceRates(this._prevIfaces.data, s.interfaces, (now - this._prevIfaces.t) / 1000, s.wan);
      }
      this._prevIfaces = { t: now, data: s.interfaces };
    }
    if (rates.newErrors > 0) this.errorLog.push([now, rates.newErrors]);
    this.errorLog = this.errorLog.filter(([t]) => now - t <= ERROR_WINDOW_MS);
    s.errorsLastHour = s.interfaces ? this.errorLog.reduce((a, [, n]) => a + n, 0) : null;
    s.rates = rates;
    this.snap = s;

    const problems = h.evaluate(s, this._thresholds());
    await this._applyCapabilities(s, problems);
    await this._applySettings(s, forbidden);
    if (prev) this._fireTransitions(prev, s, now);
    this._diffProblems(problems, now);
    this._record(now, s);
    if (now - this._persistedAt > PERSIST_EVERY_MS) await this._persist();
    this.homey.app.notifyWidgets();
  }

  async _applyCapabilities(s, problems) {
    const gw = s.gateway;
    const status = problems.length
      ? problems.map((p) => this._problemText(p)).join(' · ')
      : this.homey.__('status.healthy');
    await Promise.all([
      this._set('alarm_generic', problems.length > 0),
      this._set('opn_status', status.length > 120 ? `${status.slice(0, 117)}…` : status),
      this._set('opn_wan_online', gw ? gw.online : null),
      this._set('opn_wan_latency', gw?.online ? gw.delayMs : null),
      this._set('opn_wan_loss', gw?.online ? gw.lossPct : null),
      this._set('opn_wan_download', s.rates.rxMbps),
      this._set('opn_wan_upload', s.rates.txMbps),
      this._set('opn_load', s.load ? s.load[1] : null),
      this._set('opn_memory', s.memoryPct),
      this._set('measure_temperature', s.temperature),
      this._set('opn_disk', s.diskPct),
      this._set('opn_states', s.states ? s.states.current : null),
      this._set('opn_services_down', s.services ? s.servicesDown.length : null),
      this._set('opn_if_errors', s.errorsLastHour),
      this._set('opn_uptime', s.uptimeSec != null ? h.formatUptime(s.uptimeSec, this._units()) : null),
    ]);
  }

  async _applySettings(s, forbidden) {
    const missing = [...new Set(forbidden.map((k) => PRIVILEGES[k]))].join(', ');
    await this._setSetting('missing_privileges', missing || this.homey.__('settings.none'));
    if (s.hostname) await this._setSetting('hostname', s.hostname);
    if (s.version) await this._setSetting('version', s.version);
  }

  _units() {
    return { d: this.homey.__('unit.d'), h: this.homey.__('unit.h'), m: this.homey.__('unit.m') };
  }

  _problemText({ code, params }) {
    if (code.startsWith('service:')) return this.homey.__('problem.service', params);
    return this.homey.__(`problem.${code}`, params);
  }

  // ------------------------------------------------------------------ transitions

  _fireTransitions(prev, s, now) {
    const tr = this.driver.triggers;
    const gwPrev = prev.gateway;
    const gw = s.gateway;
    if (gwPrev && gw && gwPrev.online && !gw.online) {
      this.wanDownSince = now;
      this.setStoreValue('wan_down_since', now).catch(this.error);
      tr.wanDown.trigger(this, { gateway: gw.name }, {}).catch(this.error);
    } else if (gwPrev && gw && !gwPrev.online && gw.online) {
      const minutes = this.wanDownSince ? Math.round((now - this.wanDownSince) / 60000) : 0;
      this.wanDownSince = null;
      this.setStoreValue('wan_down_since', null).catch(this.error);
      tr.wanUp.trigger(this, { gateway: gw.name, minutes }, {}).catch(this.error);
    }

    if (prev.services && s.services) {
      const was = new Map(prev.services.map((x) => [x.id, x.running]));
      const ignored = h.serviceMatcher(this.getSetting('ignore_services'));
      for (const svc of s.services) {
        if (!was.has(svc.id) || was.get(svc.id) === svc.running || ignored(svc)) continue;
        const tokens = { service: svc.description, id: svc.id };
        (svc.running ? tr.serviceStarted : tr.serviceStopped).trigger(this, tokens, {}).catch(this.error);
      }
    }

    if (prev.uptimeSec != null && s.uptimeSec != null && s.uptimeSec < prev.uptimeSec) {
      this._event('rebooted', this.homey.__('event.rebooted'));
      tr.rebooted.trigger(this, {}, {}).catch(this.error);
    }
  }

  _diffProblems(problems, now) {
    const tr = this.driver.triggers;
    const current = new Map(problems.map((p) => [p.code, p]));
    let changed = false;
    for (const [code, p] of current) {
      if (this.problems.has(code)) continue;
      const text = this._problemText(p);
      this.problems.set(code, { code, params: p.params, since: now });
      this._event('problem', text);
      tr.problemStarted.trigger(this, { problem: text, code }, {}).catch(this.error);
      changed = true;
    }
    for (const [code, p] of this.problems) {
      if (current.has(code)) {
        p.params = current.get(code).params; // keep latest value for display
        continue;
      }
      const text = this._problemText(p);
      const minutes = Math.round((now - p.since) / 60000);
      this.problems.delete(code);
      this._event('resolved', this.homey.__('event.resolved', { problem: text, minutes }));
      tr.problemCleared.trigger(this, { problem: text, code, minutes }, {}).catch(this.error);
      changed = true;
    }
    if (changed) this.setStoreValue('problems', [...this.problems.values()]).catch(this.error);
  }

  _event(kind, text) {
    this.events.push([Date.now(), kind, text]);
    if (this.events.length > MAX_EVENTS) this.events.splice(0, this.events.length - MAX_EVENTS);
    this.setStoreValue('events', this.events).catch(this.error);
  }

  /** 5-minute buckets for the widget: max latency/loss (spikes matter), mean throughput. */
  _record(now, s) {
    const start = now - (now % BUCKET_MS);
    const gw = s.gateway?.online ? s.gateway : null;
    let b = this._bucket;
    if (!b || b.t !== start) {
      if (b) this._flushBucket(b);
      b = {
        t: start, delay: null, loss: null, rx: 0, tx: 0, n: 0,
      };
      this._bucket = b;
    }
    if (gw?.delayMs != null) b.delay = Math.max(b.delay ?? 0, gw.delayMs);
    if (gw?.lossPct != null) b.loss = Math.max(b.loss ?? 0, gw.lossPct);
    if (s.rates.rxMbps != null) {
      b.rx += s.rates.rxMbps;
      b.tx += s.rates.txMbps ?? 0;
      b.n += 1;
    }
    if (s.gateway && !s.gateway.online) b.down = true;
  }

  _flushBucket(b) {
    const r2 = (v) => (v == null ? null : Math.round(v * 100) / 100);
    this.history.push([b.t, r2(b.delay), r2(b.loss), b.n ? r2(b.rx / b.n) : null, b.n ? r2(b.tx / b.n) : null, b.down ? 1 : 0]);
    const cutoff = Date.now() - HISTORY_MS;
    while (this.history.length && this.history[0][0] < cutoff) this.history.shift();
  }

  async _persist() {
    this._persistedAt = Date.now();
    await this.setStoreValue('history', this.history).catch(this.error);
  }

  // ------------------------------------------------------------------ flow helpers

  serviceChoices(query = '') {
    const q = String(query).toLowerCase();
    return (this.snap?.services || [])
      .filter((s) => !q || s.description.toLowerCase().includes(q) || s.id.toLowerCase().includes(q))
      .map((s) => ({
        id: s.id,
        name: s.description,
        description: `${s.id} · ${this.homey.__(s.running ? 'service.running' : 'service.stopped')}`,
      }));
  }

  isServiceRunning(id) {
    const svc = (this.snap?.services || []).find((s) => s.id === id);
    if (!svc) throw new Error(this.homey.__('device.unknown_service', { id }));
    return svc.running;
  }

  async restartService(id) {
    if (!this.client) throw new Error(this.homey.__('device.no_connection'));
    try {
      await this.client.restartService(id);
    } catch (err) {
      if (err.forbidden) throw new Error(this.homey.__('device.restart_forbidden'));
      throw err;
    }
    this._event('restart', this.homey.__('event.restart', { id }));
    this.homey.setTimeout(() => this.poll().catch(() => {}), 5000);
    return true;
  }

  // ------------------------------------------------------------------ widget

  getWidgetSnapshot() {
    const s = this.snap;
    const history = this._bucket ? [...this.history, this._bucketRow()] : this.history;
    return {
      id: this.getId(),
      name: this.getName(),
      available: this.getAvailable(),
      reachable: !this.unreachableSince,
      unreachableSince: this.unreachableSince,
      hostname: this.getSetting('hostname') || '',
      version: this.getSetting('version') || '',
      uptime: s?.uptimeSec != null ? h.formatUptime(s.uptimeSec, this._units()) : null,
      problems: [...this.problems.values()].map((p) => ({ code: p.code, text: this._problemText(p), since: p.since })),
      gateway: s?.gateway || null,
      rxMbps: s?.rates?.rxMbps ?? null,
      txMbps: s?.rates?.txMbps ?? null,
      load: s?.load || null,
      memoryPct: s?.memoryPct ?? null,
      temperature: s?.temperature ?? null,
      diskPct: s?.diskPct ?? null,
      states: s?.states || null,
      errorsLastHour: s?.errorsLastHour ?? null,
      services: (s?.services || []).map((x) => ({ id: x.id, name: x.description, running: x.running })),
      ignored: (s?.services || []).filter(h.serviceMatcher(this.getSetting('ignore_services'))).map((x) => x.id),
      history,
      events: this.events.slice(-8).reverse(),
      thresholds: this._thresholds(),
      missingPrivileges: this.getSetting('missing_privileges') || '',
    };
  }

  _bucketRow() {
    const b = this._bucket;
    const r2 = (v) => (v == null ? null : Math.round(v * 100) / 100);
    return [b.t, r2(b.delay), r2(b.loss), b.n ? r2(b.rx / b.n) : null, b.n ? r2(b.tx / b.n) : null, b.down ? 1 : 0];
  }

  // ------------------------------------------------------------------ utils

  async _set(cap, value) {
    if (!this.hasCapability(cap)) return;
    if (this.getCapabilityValue(cap) === value) return;
    await this.setCapabilityValue(cap, value).catch(this.error);
  }

  async _setSetting(key, value) {
    if (this.getSetting(key) === value) return;
    await this.setSettings({ [key]: value }).catch(this.error);
  }
}

module.exports = FirewallDevice;
