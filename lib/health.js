'use strict';

/**
 * Pure parsing + evaluation of OPNsense API responses. No Homey, no I/O - unit tested.
 * Formats verified against opnsense/core 26.7 sources and a live firewall.
 */

const num = (v) => {
  const n = Number.parseFloat(String(v ?? '').replace(',', '.'));
  return Number.isFinite(n) ? n : null;
};
const round = (v, d = 1) => (v == null ? null : Math.round(v * 10 ** d) / 10 ** d);

// --------------------------------------------------------------- gateways

/**
 * routes/gateway/status -> items[]. `status` is the untranslated dpinger state:
 * none (ok) | down | force_down | delay | loss | delay+loss | other = pending.
 * loss/delay are "0.0 %" / "1.8 ms", or "~" when monitoring is disabled.
 */
function parseGateways(json) {
  const items = Array.isArray(json?.items) ? json.items : Object.values(json?.items || json || {});
  return items.filter((g) => g && g.name).map((g) => {
    const status = String(g.status || 'none').toLowerCase();
    const monitored = g.monitor != null && g.monitor !== '~' && g.monitor !== '';
    return {
      name: g.name,
      status,
      online: status !== 'down' && status !== 'force_down',
      monitored,
      monitor: monitored ? g.monitor : null,
      lossPct: monitored ? num(g.loss) : null,
      delayMs: monitored ? num(g.delay) : null,
      stddevMs: monitored ? num(g.stddev) : null,
    };
  });
}

/** The gateway to report on: by name if set, else the first monitored one, else the first. */
function pickGateway(gateways, name) {
  if (!gateways.length) return null;
  if (name) {
    const hit = gateways.find((g) => g.name.toLowerCase() === String(name).toLowerCase());
    if (hit) return hit;
  }
  return gateways.find((g) => g.monitored) || gateways[0];
}

// --------------------------------------------------------------- services

function parseServices(json) {
  return (json?.rows || []).map((s) => ({
    id: String(s.id ?? s.name),
    name: String(s.name ?? s.id),
    description: String(s.description || s.name || s.id),
    running: Number(s.running) === 1,
    locked: Number(s.locked) === 1,
  }));
}

/** Patterns like "openssh, dpinger*" - matched against id, name and description. */
function serviceMatcher(list) {
  const pats = String(list || '').split(/[,\n]/).map((s) => s.trim().toLowerCase()).filter(Boolean)
    .map((p) => new RegExp(`^${p.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')}$`));
  return (s) => pats.some((re) => re.test(s.id.toLowerCase()) || re.test(s.name.toLowerCase())
    || re.test(s.description.toLowerCase()));
}

// --------------------------------------------------------------- system

/** "2 days, 21:53:13" | "1 day, 00:01:02" | "05:12:09" (the word "days" is translated) -> seconds */
function parseUptime(str) {
  const m = String(str || '').match(/(?:(\d+)\D+?,\s*)?(\d+):(\d{2}):(\d{2})/);
  if (!m) return null;
  return (Number(m[1] || 0) * 86400) + (Number(m[2]) * 3600) + (Number(m[3]) * 60) + Number(m[4]);
}

function formatUptime(sec, { d = 'd', h = 'h', m = 'm' } = {}) {
  if (sec == null) return '';
  const days = Math.floor(sec / 86400);
  const hours = Math.floor((sec % 86400) / 3600);
  const mins = Math.floor((sec % 3600) / 60);
  if (days) return `${days}${d} ${hours}${h}`;
  if (hours) return `${hours}${h} ${mins}${m}`;
  return `${mins}${m}`;
}

/** "0.11, 0.28, 0.32" -> [0.11, 0.28, 0.32]; "N/A" -> null */
function parseLoad(str) {
  const parts = String(str || '').split(',').map(num);
  return parts.length === 3 && parts.every((v) => v != null) ? parts : null;
}

function memoryPct(json) {
  const total = num(json?.memory?.total);
  const used = num(json?.memory?.used);
  return total && used != null ? round((used / total) * 100) : null;
}

/** Highest reported sensor, °C. */
function maxTemperature(json) {
  const temps = (Array.isArray(json) ? json : []).map((t) => num(t.temperature)).filter((v) => v != null);
  return temps.length ? round(Math.max(...temps)) : null;
}

function rootDiskPct(json) {
  const root = (json?.devices || []).find((d) => d.mountpoint === '/');
  return root ? num(root.used_pct) : null;
}

function parseStates(json) {
  const current = num(json?.current);
  const limit = num(json?.limit);
  return current == null ? null : {
    current, limit, pct: limit ? round((current / limit) * 100, 2) : null,
  };
}

function parseVersion(json) {
  const v = (json?.versions || []).find((s) => /^OPNsense/i.test(s));
  return { hostname: json?.name || '', version: v ? v.replace(/^OPNsense\s+/i, '') : '' };
}

// --------------------------------------------------------------- interfaces

/**
 * get_interface_statistics -> one entry per link-level row ("<Link#n>"); address rows are skipped.
 * Keys look like "[WAN] (pppoe0) / pppoe0" or "[igb2] / 7c:..." (unassigned).
 */
function parseInterfaces(json) {
  const out = {};
  for (const [key, v] of Object.entries(json?.statistics || {})) {
    if (!/Link#/.test(String(v.network || ''))) continue;
    const label = (key.match(/^\[([^\]]+)\]\s*\(/) || [])[1] || null; // assigned description only
    out[v.name] = {
      device: v.name,
      label,
      rxBytes: Number(v['received-bytes']) || 0,
      txBytes: Number(v['sent-bytes']) || 0,
      errors: (Number(v['received-errors']) || 0) + (Number(v['send-errors']) || 0)
        + (Number(v['dropped-packets']) || 0),
    };
  }
  return out;
}

/** Finds the WAN interface: by description ("WAN"), device name ("pppoe0") or the first labelled WAN*. */
function pickInterface(ifaces, wanted = 'WAN') {
  const list = Object.values(ifaces);
  const w = String(wanted || 'WAN').toLowerCase();
  return list.find((i) => (i.label || '').toLowerCase() === w)
    || list.find((i) => i.device.toLowerCase() === w)
    || list.find((i) => /^wan/i.test(i.label || ''))
    || null;
}

/**
 * Rates between two interface snapshots.
 * @returns {{rxMbps: number|null, txMbps: number|null, newErrors: number, perInterface: object}}
 */
function interfaceRates(prev, cur, dtSec, wan) {
  const perInterface = {};
  let newErrors = 0;
  for (const [dev, c] of Object.entries(cur)) {
    const p = prev?.[dev];
    if (!p) continue;
    // Counters reset on reboot / interface re-creation: ignore negative deltas.
    const e = c.errors - p.errors;
    if (e > 0 && c.label) { // only assigned interfaces count; lo0/enc0/pflog are noise
      newErrors += e;
      perInterface[dev] = { label: c.label, newErrors: e };
    }
  }
  let rxMbps = null;
  let txMbps = null;
  if (wan && prev?.[wan.device] && dtSec > 0) {
    const p = prev[wan.device];
    const rx = wan.rxBytes - p.rxBytes;
    const tx = wan.txBytes - p.txBytes;
    if (rx >= 0) rxMbps = round((rx * 8) / dtSec / 1e6, 2);
    if (tx >= 0) txMbps = round((tx * 8) / dtSec / 1e6, 2);
  }
  return {
    rxMbps, txMbps, newErrors, perInterface,
  };
}

// --------------------------------------------------------------- evaluation

const DEFAULT_THRESHOLDS = Object.freeze({
  latencyMs: 50,
  lossPct: 5,
  temperatureC: 75,
  memoryPct: 90,
  diskPct: 85,
  statesPct: 50,
  load: 4,
  errorsPerHour: 100,
});

/**
 * Turns a parsed snapshot into a list of problems. Each problem has a stable `code`
 * (used for change detection and flow tokens) and `params` for the translated text.
 */
function evaluate(s, t = DEFAULT_THRESHOLDS) {
  const problems = [];
  const add = (code, params = {}) => problems.push({ code, params });

  const gw = s.gateway;
  if (gw) {
    if (!gw.online) add('wan_down', { name: gw.name });
    else {
      if (gw.lossPct != null && gw.lossPct >= t.lossPct) add('wan_loss', { value: gw.lossPct });
      if (gw.delayMs != null && gw.delayMs >= t.latencyMs) add('wan_latency', { value: gw.delayMs });
    }
  }
  for (const svc of s.servicesDown || []) add(`service:${svc.id}`, { name: svc.description });
  if (s.temperature != null && s.temperature >= t.temperatureC) add('temperature', { value: s.temperature });
  if (s.memoryPct != null && s.memoryPct >= t.memoryPct) add('memory', { value: s.memoryPct });
  if (s.diskPct != null && s.diskPct >= t.diskPct) add('disk', { value: s.diskPct });
  if (s.states?.pct != null && s.states.pct >= t.statesPct) add('states', { value: s.states.pct });
  if (s.load && s.load[1] >= t.load) add('load', { value: s.load[1] });
  if (s.errorsLastHour != null && s.errorsLastHour >= t.errorsPerHour) add('if_errors', { value: s.errorsLastHour });
  return problems;
}

/**
 * Builds the device-level snapshot from raw API data.
 * @param {object} raw responses keyed like OPNsenseClient.snapshot()
 * @param {object} opts { gatewayName, wanInterface, ignoreServices }
 */
function parseSnapshot(raw, { gatewayName, wanInterface, ignoreServices } = {}) {
  const gateways = raw.gateway ? parseGateways(raw.gateway) : [];
  const services = raw.services ? parseServices(raw.services) : null;
  const ignored = serviceMatcher(ignoreServices);
  const interfaces = raw.interfaces ? parseInterfaces(raw.interfaces) : null;
  return {
    gateways,
    gateway: pickGateway(gateways, gatewayName),
    services,
    servicesDown: services ? services.filter((x) => !x.running && !ignored(x)) : [],
    uptimeSec: raw.time ? parseUptime(raw.time.uptime) : null,
    load: raw.time ? parseLoad(raw.time.loadavg) : null,
    memoryPct: raw.resources ? memoryPct(raw.resources) : null,
    temperature: raw.temperature ? maxTemperature(raw.temperature) : null,
    diskPct: raw.disk ? rootDiskPct(raw.disk) : null,
    states: raw.states ? parseStates(raw.states) : null,
    ...(raw.info ? parseVersion(raw.info) : { hostname: '', version: '' }),
    interfaces,
    wan: interfaces ? pickInterface(interfaces, wanInterface) : null,
  };
}

module.exports = {
  DEFAULT_THRESHOLDS,
  parseGateways,
  pickGateway,
  parseServices,
  serviceMatcher,
  parseUptime,
  formatUptime,
  parseLoad,
  memoryPct,
  maxTemperature,
  rootDiskPct,
  parseStates,
  parseVersion,
  parseInterfaces,
  pickInterface,
  interfaceRates,
  evaluate,
  parseSnapshot,
};
