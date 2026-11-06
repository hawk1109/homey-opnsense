'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const { OPNsenseClient } = require('../lib/OPNsenseClient');

const cert = fs.readFileSync(path.join(__dirname, 'fixtures', 'tls-cert.pem'));
const key = fs.readFileSync(path.join(__dirname, 'fixtures', 'tls-key.pem'));
const fingerprint = new crypto.X509Certificate(cert).fingerprint256;

/** Self-signed test "firewall". Records every request it receives. */
function startServer() {
  const seen = [];
  const server = https.createServer({ key, cert }, (req, res) => {
    seen.push({ method: req.method, url: req.url, auth: req.headers.authorization });
    const ok = req.headers.authorization === `Basic ${Buffer.from('k:s').toString('base64')}`;
    if (!ok) { res.writeHead(401); res.end(); return; }
    if (req.url === '/api/core/service/search') { res.writeHead(403); res.end('{}'); return; }
    if (req.url.startsWith('/api/core/service/restart/')) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{"response":"OK"}');
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ items: [{ name: 'WAN', status: 'none' }] }));
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, seen, url: `https://127.0.0.1:${server.address().port}` })));
}

test('probe reads the certificate without sending a request', async () => {
  const { server, seen, url } = await startServer();
  try {
    const c = await OPNsenseClient.probeCertificate(url);
    assert.equal(c.fingerprint, fingerprint);
    assert.equal(c.subject, 'test-firewall');
    assert.equal(c.trusted, false);
    assert.equal(seen.length, 0);
  } finally { server.close(); }
});

test('pinned fingerprint: request succeeds with basic auth', async () => {
  const { server, url } = await startServer();
  try {
    const c = new OPNsenseClient({ url, key: 'k', secret: 's', fingerprint });
    const r = await c.gatewayStatus();
    assert.equal(r.items[0].name, 'WAN');
  } finally { server.close(); }
});

test('wrong pin: connection refused before any HTTP (credentials never leave)', async () => {
  const { server, seen, url } = await startServer();
  try {
    const c = new OPNsenseClient({ url, key: 'k', secret: 's', fingerprint: 'AA:BB' });
    await assert.rejects(c.gatewayStatus(), (e) => e.cert === true);
    assert.equal(seen.length, 0);
  } finally { server.close(); }
});

test('no pin: untrusted self-signed certificate is rejected', async () => {
  const { server, seen, url } = await startServer();
  try {
    const c = new OPNsenseClient({ url, key: 'k', secret: 's' });
    await assert.rejects(c.gatewayStatus(), (e) => e.cert === true);
    assert.equal(seen.length, 0);
  } finally { server.close(); }
});

test('401 is auth, 403 is a missing privilege, snapshot keeps going on 403', async () => {
  const { server, url } = await startServer();
  try {
    const bad = new OPNsenseClient({ url, key: 'k', secret: 'wrong', fingerprint });
    await assert.rejects(bad.gatewayStatus(), (e) => e.auth === true);

    const c = new OPNsenseClient({ url, key: 'k', secret: 's', fingerprint });
    await assert.rejects(c.services(), (e) => e.forbidden === true);
    const snap = await c.snapshot();
    assert.deepEqual(snap.forbidden, ['services']);
    assert.ok(snap.raw.gateway);
  } finally { server.close(); }
});

test('restart posts to the service id, multi-instance path kept', async () => {
  const { server, seen, url } = await startServer();
  try {
    const c = new OPNsenseClient({ url, key: 'k', secret: 's', fingerprint });
    await c.restartService('dpinger/WAN_PPPOE');
    assert.deepEqual(seen.at(-1).method, 'POST');
    assert.equal(seen.at(-1).url, '/api/core/service/restart/dpinger/WAN_PPPOE');
  } finally { server.close(); }
});

test('unreachable host is a network error', async () => {
  const c = new OPNsenseClient({ url: 'https://127.0.0.1:1', key: 'k', secret: 's', fingerprint });
  await assert.rejects(c.gatewayStatus(), (e) => e.network === true);
});
