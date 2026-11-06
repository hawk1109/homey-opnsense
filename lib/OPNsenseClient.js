'use strict';

/**
 * Client for the OPNsense REST API (key/secret basic auth).
 *
 * TLS: a home firewall usually serves a self-signed or private-CA certificate.
 * Instead of turning verification off, the client pins the certificate's
 * SHA-256 fingerprint (trust on first use, confirmed by the user at pairing).
 * The TLS socket is opened and checked *before* any HTTP bytes - including the
 * Authorization header - are written. Without a pin, normal CA verification applies.
 */

const tls = require('node:tls');
const http = require('node:http');
const net = require('node:net');

const REQUEST_TIMEOUT_MS = 15000;

class OPNError extends Error {
  /**
   * @param {string} message
   * @param {object} [o]
   * @param {boolean} [o.auth] 401 - key/secret wrong
   * @param {boolean} [o.forbidden] 403 - user lacks the privilege for this endpoint
   * @param {boolean} [o.cert] certificate does not match the pinned fingerprint / fails verification
   * @param {boolean} [o.network] firewall not reachable
   * @param {number} [o.status]
   */
  constructor(message, {
    auth = false, forbidden = false, cert = false, network = false, status, cause,
  } = {}) {
    super(message);
    this.name = 'OPNError';
    Object.assign(this, {
      auth, forbidden, cert, network, status,
    });
    if (cause) this.cause = cause;
  }
}

const normFp = (fp) => String(fp || '').replace(/[^0-9a-f]/gi, '').toUpperCase();
const fmtFp = (fp) => normFp(fp).match(/.{2}/g)?.join(':') || '';

function parseUrl(input) {
  const raw = String(input || '').trim();
  const u = new URL(/^[a-z]+:\/\//i.test(raw) ? raw : `https://${raw}`);
  if (u.protocol !== 'https:') throw new OPNError('Only https:// is supported');
  return { host: u.hostname.replace(/^\[|\]$/g, ''), port: Number(u.port) || 443 };
}

class OPNsenseClient {
  /**
   * @param {object} opts
   * @param {string} opts.url e.g. https://192.168.178.1 or https://fw.home.lan:8443
   * @param {string} opts.key API key
   * @param {string} opts.secret API secret
   * @param {string} [opts.fingerprint] pinned SHA-256 certificate fingerprint
   * @param {(...a: any[]) => void} [opts.log]
   */
  constructor({
    url, key, secret, fingerprint, log,
  }) {
    const { host, port } = parseUrl(url);
    this.host = host;
    this.port = port;
    this.key = key;
    this.secret = secret;
    this.fingerprint = normFp(fingerprint);
    this.log = log || (() => {});
  }

  // ---------------------------------------------------------------- TLS

  /**
   * Reads the server certificate without sending anything. Used at pairing.
   * @returns {Promise<{fingerprint: string, subject: string, issuer: string, validTo: string,
   *   altNames: string, trusted: boolean, trustError: string|null}>}
   */
  static probeCertificate(url) {
    const { host, port } = parseUrl(url);
    return new Promise((resolve, reject) => {
      const sock = tls.connect({
        host, port, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: false,
      });
      sock.setTimeout(REQUEST_TIMEOUT_MS, () => sock.destroy(new Error('timeout')));
      sock.once('secureConnect', () => {
        const c = sock.getPeerCertificate();
        const identityErr = c && c.subject ? tls.checkServerIdentity(host, c) : null;
        const trustError = sock.authorizationError
          ? String(sock.authorizationError)
          : (identityErr ? identityErr.message : null);
        sock.end();
        if (!c || !c.fingerprint256) {
          reject(new OPNError('The firewall did not present a certificate', { cert: true }));
          return;
        }
        resolve({
          fingerprint: fmtFp(c.fingerprint256),
          subject: (c.subject && (c.subject.CN || c.subject.O)) || '',
          issuer: (c.issuer && (c.issuer.CN || c.issuer.O)) || '',
          validTo: c.valid_to || '',
          altNames: c.subjectaltname || '',
          trusted: !trustError,
          trustError,
        });
      });
      sock.once('error', (err) => reject(new OPNError(`Cannot reach ${host}:${port} (${err.message})`, { network: true, cause: err })));
    });
  }

  _connect() {
    return new Promise((resolve, reject) => {
      const pinned = !!this.fingerprint;
      const sock = tls.connect({
        host: this.host,
        port: this.port,
        servername: net.isIP(this.host) ? undefined : this.host,
        rejectUnauthorized: !pinned,
        ALPNProtocols: ['http/1.1'],
      });
      const fail = (err) => { sock.destroy(); reject(err); };
      sock.setTimeout(REQUEST_TIMEOUT_MS, () => fail(new OPNError(`Timeout connecting to ${this.host}`, { network: true })));
      sock.once('secureConnect', () => {
        if (pinned) {
          const fp = normFp(sock.getPeerCertificate().fingerprint256);
          if (fp !== this.fingerprint) {
            fail(new OPNError('The firewall certificate has changed. Use Repair to trust the new certificate.', { cert: true }));
            return;
          }
        }
        sock.setTimeout(0);
        resolve(sock);
      });
      sock.once('error', (err) => {
        const certErr = /certificate|self.signed|CERT_|altname/i.test(err.message || err.code || '');
        reject(new OPNError(
          certErr ? `Certificate not trusted: ${err.message}` : `Cannot reach ${this.host} (${err.message})`,
          { cert: certErr, network: !certErr, cause: err },
        ));
      });
    });
  }

  // ---------------------------------------------------------------- transport

  async _request(path, { method = 'GET', body } = {}) {
    const socket = await this._connect();
    const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
    const auth = Buffer.from(`${this.key}:${this.secret}`).toString('base64');

    return new Promise((resolve, reject) => {
      const req = http.request({
        method,
        path: `/api/${path}`,
        headers: {
          Host: this.port === 443 ? this.host : `${this.host}:${this.port}`,
          Authorization: `Basic ${auth}`,
          Accept: 'application/json',
          Connection: 'close',
          ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': payload.length } : {}),
        },
        // No agent: Node then uses createConnection, i.e. our already-verified TLS socket.
        createConnection: () => socket,
        timeout: REQUEST_TIMEOUT_MS,
      }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          if (res.statusCode === 401) {
            reject(new OPNError('API key or secret rejected (HTTP 401)', { auth: true, status: 401 }));
          } else if (res.statusCode === 403) {
            reject(new OPNError(`No privilege for /api/${path} (HTTP 403)`, { forbidden: true, status: 403 }));
          } else if (res.statusCode < 200 || res.statusCode >= 300) {
            reject(new OPNError(`/api/${path} responded HTTP ${res.statusCode}`, { status: res.statusCode }));
          } else {
            try {
              resolve(JSON.parse(text));
            } catch {
              reject(new OPNError(`Unexpected non-JSON response from /api/${path}: ${text.slice(0, 120)}`));
            }
          }
        });
        res.on('error', reject);
      });
      req.on('timeout', () => req.destroy(new OPNError(`Timeout on /api/${path}`, { network: true })));
      req.on('error', (err) => reject(err instanceof OPNError ? err : new OPNError(err.message, { network: true, cause: err })));
      if (payload) req.write(payload);
      req.end();
    });
  }

  // ---------------------------------------------------------------- endpoints

  /** Privilege: System: Gateways */
  gatewayStatus() { return this._request('routes/gateway/status'); }

  /** Privilege: Status: Services */
  services() { return this._request('core/service/search'); }

  /** Privilege: Status: Services. `id` as returned by services(), e.g. "igmpproxy" or "dpinger/WAN_PPPOE". */
  restartService(id) {
    const path = String(id).split('/').map(encodeURIComponent).join('/');
    return this._request(`core/service/restart/${path}`, { method: 'POST', body: {} });
  }

  /** Privilege: Lobby: Dashboard (all system_* and pf_states) */
  systemTime() { return this._request('diagnostics/system/system_time'); }

  systemResources() { return this._request('diagnostics/system/system_resources'); }

  systemTemperature() { return this._request('diagnostics/system/system_temperature'); }

  systemDisk() { return this._request('diagnostics/system/system_disk'); }

  systemInformation() { return this._request('diagnostics/system/system_information'); }

  pfStates() { return this._request('diagnostics/firewall/pf_states'); }

  /** Privilege: Diagnostics: Netstat */
  interfaceStatistics() { return this._request('diagnostics/interface/get_interface_statistics'); }

  /**
   * Fetches every endpoint independently; a missing privilege only blanks that part.
   * @returns {Promise<{raw: object, forbidden: string[], errors: OPNError[]}>}
   */
  async snapshot() {
    const calls = {
      gateway: () => this.gatewayStatus(),
      services: () => this.services(),
      time: () => this.systemTime(),
      resources: () => this.systemResources(),
      temperature: () => this.systemTemperature(),
      disk: () => this.systemDisk(),
      info: () => this.systemInformation(),
      states: () => this.pfStates(),
      interfaces: () => this.interfaceStatistics(),
    };
    const keys = Object.keys(calls);
    // Sequential: the firewall is small and this runs once a minute.
    const raw = {};
    const forbidden = [];
    const errors = [];
    for (const k of keys) {
      try {
        raw[k] = await calls[k]();
      } catch (err) {
        if (err.forbidden) forbidden.push(k);
        else errors.push(err);
        // A dead firewall or bad credentials fail every call: stop early.
        if (err.network || err.auth || err.cert) throw err;
      }
    }
    return { raw, forbidden, errors };
  }
}

/** Which OPNsense privilege covers which snapshot part (verified against opnsense/core ACL.xml). */
const PRIVILEGES = Object.freeze({
  gateway: 'System: Gateways',
  services: 'Status: Services',
  time: 'Lobby: Dashboard',
  resources: 'Lobby: Dashboard',
  temperature: 'Lobby: Dashboard',
  disk: 'Lobby: Dashboard',
  info: 'Lobby: Dashboard',
  states: 'Lobby: Dashboard',
  interfaces: 'Diagnostics: Netstat',
});

module.exports = {
  OPNsenseClient, OPNError, PRIVILEGES, fmtFp, normFp,
};
