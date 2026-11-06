'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');

const h = require('../lib/health');

// Fixtures: real responses from an OPNsense 26.7.8 firewall (KPN PPPoE + IPTV VLAN).
const load = (f) => JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', `${f}.json`), 'utf8'));
const raw = Object.fromEntries(['gateway', 'services', 'time', 'resources', 'temperature', 'disk', 'info', 'states', 'interfaces']
  .map((k) => [k, load(k)]));

test('gateway: monitored PPPoE gateway', () => {
  const [gw] = h.parseGateways(raw.gateway);
  assert.deepEqual(gw, {
    name: 'WAN_PPPOE', status: 'none', online: true, monitored: true, monitor: '1.1.1.1',
    lossPct: 0, delayMs: 1.8, stddevMs: 0.1,
  });
});

test('gateway: monitoring disabled reports "~" and no numbers', () => {
  const [gw] = h.parseGateways({ items: [{ name: 'WAN', status: 'none', loss: '~', delay: '~', stddev: '~', monitor: '~' }] });
  assert.equal(gw.monitored, false);
  assert.equal(gw.delayMs, null);
  assert.equal(gw.online, true);
});

test('gateway: down and force_down are offline; delay/loss are online-but-degraded', () => {
  const st = (status) => h.parseGateways({ items: [{ name: 'W', status, monitor: '1.1.1.1', loss: '100.0 %', delay: '0.0 ms' }] })[0].online;
  assert.equal(st('down'), false);
  assert.equal(st('force_down'), false);
  assert.equal(st('delay+loss'), true);
});

test('services: parsed, multi-instance ids kept', () => {
  const svcs = h.parseServices(raw.services);
  assert.equal(svcs.length, 18);
  assert.ok(svcs.find((s) => s.id === 'dpinger/WAN_PPPOE'));
  assert.ok(svcs.every((s) => s.running));
  const igmp = svcs.find((s) => s.id === 'igmpproxy');
  assert.equal(igmp.description, 'IGMP Proxy');
  assert.equal(igmp.locked, false);
});

test('service ignore patterns match id, name or description, with wildcards', () => {
  const m = h.serviceMatcher('openssh, dpinger*,  Tailscale');
  const svcs = h.parseServices(raw.services);
  assert.deepEqual(svcs.filter(m).map((s) => s.id).sort(),
    ['dpinger/:watcher:', 'dpinger/WAN_PPPOE', 'openssh', 'tailscale']);
  assert.equal(svcs.filter(h.serviceMatcher('')).length, 0);
});

test('uptime: with and without days, translated day word', () => {
  assert.equal(h.parseUptime('2 days, 21:53:13'), (2 * 86400) + (21 * 3600) + (53 * 60) + 13);
  assert.equal(h.parseUptime('1 dag, 00:00:05'), 86405);
  assert.equal(h.parseUptime('05:12:09'), (5 * 3600) + (12 * 60) + 9);
  assert.equal(h.parseUptime('N/A'), null);
  assert.equal(h.formatUptime(h.parseUptime('2 days, 21:53:13')), '2d 21h');
  assert.equal(h.formatUptime(3700), '1h 1m');
});

test('system figures', () => {
  assert.deepEqual(h.parseLoad(raw.time.loadavg), [0.11, 0.28, 0.32]);
  assert.equal(h.parseLoad('N/A'), null);
  assert.equal(h.memoryPct(raw.resources), 31);
  assert.equal(h.maxTemperature(raw.temperature), 38.1);
  assert.equal(h.rootDiskPct(raw.disk), 3);
  assert.deepEqual(h.parseStates(raw.states), { current: 1260, limit: 389200, pct: 0.32 });
  assert.deepEqual(h.parseVersion(raw.info), { hostname: 'sophos.home.lan', version: '26.7.8_2-amd64' });
});

test('interfaces: link rows only, labels from assignments', () => {
  const ifs = h.parseInterfaces(raw.interfaces);
  assert.equal(ifs.igb0.label, 'LAN');
  assert.equal(ifs.igb0.rxBytes, 32449138517); // link row, not the address row
  assert.equal(ifs.igb2.label, null); // unassigned parent of the VLANs
  assert.equal(ifs.vlan02.label, null);
  assert.equal(ifs.vlan01.label, 'IPTV');
  assert.equal(h.pickInterface(ifs).device, 'pppoe0');
  assert.equal(h.pickInterface(ifs, 'IPTV').device, 'vlan01');
  assert.equal(h.pickInterface(ifs, 'pppoe0').device, 'pppoe0');
});

test('interface rates: WAN throughput and new errors on assigned interfaces only', () => {
  const prev = h.parseInterfaces(raw.interfaces);
  const cur = structuredClone(prev);
  cur.pppoe0.rxBytes += 750e6 / 8 * 60; // 750 Mbit/s for 60 s
  cur.pppoe0.txBytes += 50e6 / 8 * 60;
  cur.vlan02.errors += 500; // unassigned: ignored
  cur.vlan01.errors += 3; // IPTV
  const r = h.interfaceRates(prev, cur, 60, cur.pppoe0);
  assert.equal(r.rxMbps, 750);
  assert.equal(r.txMbps, 50);
  assert.equal(r.newErrors, 3);
  assert.deepEqual(r.perInterface, { vlan01: { label: 'IPTV', newErrors: 3 } });
});

test('interface rates: counter reset after reboot gives no negative numbers', () => {
  const prev = h.parseInterfaces(raw.interfaces);
  const cur = structuredClone(prev);
  cur.pppoe0.rxBytes = 1000;
  cur.vlan01.errors = 0;
  const r = h.interfaceRates(prev, cur, 60, cur.pppoe0);
  assert.equal(r.rxMbps, null);
  assert.equal(r.newErrors, 0);
});

test('snapshot of the healthy live firewall has no problems', () => {
  const s = h.parseSnapshot(raw);
  assert.equal(s.gateway.name, 'WAN_PPPOE');
  assert.equal(s.wan.device, 'pppoe0');
  assert.deepEqual(h.evaluate(s), []);
});

test('evaluate: stopped service, degraded WAN and thresholds', () => {
  const r = structuredClone(raw);
  r.services.rows.find((x) => x.id === 'igmpproxy').running = 0;
  r.services.rows.find((x) => x.id === 'openssh').running = 0;
  r.gateway.items[0].delay = '80.2 ms';
  r.temperature[0].temperature = '81.0';
  const s = h.parseSnapshot(r, { ignoreServices: 'openssh' });
  const codes = h.evaluate(s).map((p) => p.code);
  assert.deepEqual(codes, ['wan_latency', 'service:igmpproxy', 'temperature']);
});

test('evaluate: WAN down suppresses latency/loss noise', () => {
  const r = structuredClone(raw);
  Object.assign(r.gateway.items[0], { status: 'down', loss: '100.0 %', delay: '0.0 ms' });
  const codes = h.evaluate(h.parseSnapshot(r)).map((p) => p.code);
  assert.deepEqual(codes, ['wan_down']);
});

test('missing privileges leave fields null instead of failing', () => {
  const s = h.parseSnapshot({ gateway: raw.gateway });
  assert.equal(s.services, null);
  assert.equal(s.memoryPct, null);
  assert.equal(s.wan, null);
  assert.deepEqual(h.evaluate(s), []);
});
