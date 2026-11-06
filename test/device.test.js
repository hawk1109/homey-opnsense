'use strict';

/**
 * Runs drivers/firewall/device.js against a minimal fake of the Homey SDK, fed with
 * the live-firewall fixtures. Covers the state machine: problems, triggers,
 * unreachable/reachable, reboot detection, throughput and widget data.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const Module = require('node:module');

const en = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'locales', 'en.json'), 'utf8'));
const translate = (key, t = {}) => {
  let v = key.split('.').reduce((o, k) => (o ? o[k] : undefined), en);
  if (typeof v !== 'string') return key;
  for (const [k, val] of Object.entries(t)) v = v.split(`__${k}__`).join(String(val));
  return v;
};

class FakeDevice {
  constructor({ store, settings }) {
    this._store = { ...store };
    this._settings = { ...settings };
    this._caps = {};
    this._available = true;
    this.fired = [];
    const trig = (name) => ({ trigger: async (dev, tokens) => { this.fired.push([name, tokens]); } });
    this.driver = {
      triggers: Object.fromEntries(['problemStarted', 'problemCleared', 'wanDown', 'wanUp', 'serviceStopped',
        'serviceStarted', 'unreachable', 'reachable', 'rebooted'].map((n) => [n, trig(n)])),
    };
    this.homey = {
      __: translate,
      setTimeout: () => 0,
      setInterval: () => 0,
      clearInterval: () => {},
      app: { notifyWidgets: () => {} },
    };
  }

  log() {}

  error(e) { throw e; }

  getStore() { return this._store; }

  getStoreValue(k) { return this._store[k]; }

  async setStoreValue(k, v) { this._store[k] = v; }

  getSetting(k) { return this._settings[k]; }

  getSettings() { return this._settings; }

  async setSettings(o) { Object.assign(this._settings, o); }

  hasCapability() { return true; }

  async addCapability() {}

  getCapabilityValue(c) { return this._caps[c]; }

  async setCapabilityValue(c, v) { this._caps[c] = v; }

  getAvailable() { return this._available; }

  async setAvailable() { this._available = true; }

  async setUnavailable() { this._available = false; }

  getId() { return 'dev1'; }

  getName() { return 'sophos'; }
}

// Make require('homey') resolve to the fake.
const origResolve = Module._resolveFilename;
Module._resolveFilename = function resolve(request, ...rest) {
  if (request === 'homey') return 'homey';
  return origResolve.call(this, request, ...rest);
};
require.cache.homey = { id: 'homey', filename: 'homey', loaded: true, exports: { Device: FakeDevice } };
const FirewallDevice = require('../drivers/firewall/device');

const load = (f) => JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', `${f}.json`), 'utf8'));
const rawFixture = () => Object.fromEntries(['gateway', 'services', 'time', 'resources', 'temperature', 'disk', 'info', 'states', 'interfaces']
  .map((k) => [k, load(k)]));

const SETTINGS = {
  poll_interval: 60, gateway_name: '', wan_interface: 'WAN', ignore_services: 'openssh',
  th_latency: 50, th_loss: 5, th_temperature: 75, th_memory: 90, th_disk: 85, th_states: 50, th_load: 4, th_errors: 100,
};

async function makeDevice() {
  const d = new FirewallDevice({ store: { url: 'https://192.0.2.1', key: 'k', secret: 's', fingerprint: 'AA' }, settings: SETTINGS });
  await d.onInit();
  // Replace the network client with a scripted one.
  d.queue = [];
  d.client = {
    snapshot: async () => {
      const next = d.queue.shift();
      if (next instanceof Error) throw next;
      return { raw: next, forbidden: [] };
    },
  };
  return d;
}

test('healthy firewall: capabilities set, no problems, no triggers', async () => {
  const d = await makeDevice();
  d.queue.push(rawFixture());
  await d.poll();
  assert.equal(d.getCapabilityValue('alarm_generic'), false);
  assert.equal(d.getCapabilityValue('opn_status'), 'Healthy');
  assert.equal(d.getCapabilityValue('opn_wan_online'), true);
  assert.equal(d.getCapabilityValue('opn_wan_latency'), 1.8);
  assert.equal(d.getCapabilityValue('opn_memory'), 31);
  assert.equal(d.getCapabilityValue('measure_temperature'), 38.1);
  assert.equal(d.getCapabilityValue('opn_services_down'), 0);
  assert.equal(d.getCapabilityValue('opn_uptime'), '2d 21h');
  assert.equal(d.getSetting('hostname'), 'sophos.home.lan');
  assert.deepEqual(d.fired, []);
});

test('igmpproxy stops and comes back: service + problem triggers with duration', async () => {
  const d = await makeDevice();
  const ok = rawFixture();
  const down = rawFixture();
  down.services.rows.find((s) => s.id === 'igmpproxy').running = 0;
  // openssh is ignored: its stop must not raise anything
  down.services.rows.find((s) => s.id === 'openssh').running = 0;
  d.queue.push(ok, down, rawFixture());
  await d.poll();
  await d.poll();
  assert.equal(d.getCapabilityValue('alarm_generic'), true);
  assert.equal(d.getCapabilityValue('opn_status'), 'IGMP Proxy stopped');
  assert.equal(d.getCapabilityValue('opn_services_down'), 1);
  assert.deepEqual(d.fired.map((f) => f[0]), ['serviceStopped', 'problemStarted']);
  assert.deepEqual(d.fired[0][1], { service: 'IGMP Proxy', id: 'igmpproxy' });

  d.fired = [];
  await d.poll();
  assert.equal(d.getCapabilityValue('alarm_generic'), false);
  assert.deepEqual(d.fired.map((f) => f[0]), ['serviceStarted', 'problemCleared']);
  assert.equal(d.fired[1][1].code, 'service:igmpproxy');
  assert.equal(typeof d.fired[1][1].minutes, 'number');
});

test('WAN down/up triggers, latency/loss blanked while down', async () => {
  const d = await makeDevice();
  const down = rawFixture();
  Object.assign(down.gateway.items[0], { status: 'down', loss: '100.0 %' });
  d.queue.push(rawFixture(), down, rawFixture());
  await d.poll();
  await d.poll();
  assert.equal(d.getCapabilityValue('opn_wan_online'), false);
  assert.equal(d.getCapabilityValue('opn_wan_latency'), null);
  assert.equal(d.getCapabilityValue('opn_status'), 'Internet down (WAN_PPPOE)');
  await d.poll();
  const names = d.fired.map((f) => f[0]);
  assert.deepEqual(names, ['wanDown', 'problemStarted', 'wanUp', 'problemCleared']);
});

test('unreachable only after two failed polls, then reachable again', async () => {
  const d = await makeDevice();
  const netErr = Object.assign(new Error('Cannot reach'), { network: true });
  d.queue.push(rawFixture(), netErr, netErr, netErr, rawFixture());
  await d.poll();
  await d.poll();
  assert.deepEqual(d.fired, []); // one blip is not an outage
  await d.poll();
  await d.poll();
  assert.deepEqual(d.fired.map((f) => f[0]), ['unreachable']); // fired once
  assert.equal(d.getCapabilityValue('alarm_generic'), true);
  assert.equal(d.getCapabilityValue('opn_status'), 'Firewall unreachable');
  await d.poll();
  assert.deepEqual(d.fired.map((f) => f[0]), ['unreachable', 'reachable']);
  assert.equal(d.getCapabilityValue('alarm_generic'), false);
});

test('auth and certificate errors make the device unavailable (repair needed)', async () => {
  const d = await makeDevice();
  d.queue.push(Object.assign(new Error('x'), { auth: true }));
  await d.poll();
  assert.equal(d.getAvailable(), false);
  d.queue.push(rawFixture());
  await d.poll();
  assert.equal(d.getAvailable(), true);
  d.queue.push(Object.assign(new Error('x'), { cert: true }));
  await d.poll();
  assert.equal(d.getAvailable(), false);
});

test('reboot detected from uptime going backwards', async () => {
  const d = await makeDevice();
  const after = rawFixture();
  after.time.uptime = '00:02:10';
  d.queue.push(rawFixture(), after);
  await d.poll();
  await d.poll();
  assert.ok(d.fired.some((f) => f[0] === 'rebooted'));
  assert.equal(d.getCapabilityValue('opn_uptime'), '2m');
});

test('throughput from WAN counters, widget snapshot carries history and events', async () => {
  const d = await makeDevice();
  const a = rawFixture();
  const b = rawFixture();
  const wan = b.interfaces.statistics['[WAN] (pppoe0) / pppoe0'];
  wan['received-bytes'] += 1e9; // 1 GB more
  d.queue.push(a, b);
  await d.poll();
  d._prevIfaces.t -= 80 * 1000; // pretend 80 s passed
  await d.poll();
  assert.equal(d.getCapabilityValue('opn_wan_download'), 100); // 8e9 bit / 80 s
  const w = d.getWidgetSnapshot();
  assert.equal(w.hostname, 'sophos.home.lan');
  assert.equal(w.rxMbps, 100);
  assert.equal(w.history.length, 1); // current bucket
  assert.equal(w.history[0][3], 100);
  assert.deepEqual(w.ignored, ['openssh']);
  assert.equal(w.services.length, 18);
});

test('service autocomplete and running condition', async () => {
  const d = await makeDevice();
  d.queue.push(rawFixture());
  await d.poll();
  const hits = d.serviceChoices('igmp');
  assert.deepEqual(hits.map((x) => x.id), ['igmpproxy']);
  assert.equal(hits[0].name, 'IGMP Proxy');
  assert.equal(d.isServiceRunning('igmpproxy'), true);
  assert.throws(() => d.isServiceRunning('nope'));
});
