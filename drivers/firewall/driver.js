'use strict';

const Homey = require('homey');
const { OPNsenseClient, PRIVILEGES } = require('../../lib/OPNsenseClient');
const { parseVersion } = require('../../lib/health');

class FirewallDriver extends Homey.Driver {
  async onInit() {
    this._registerFlows();
  }

  _registerFlows() {
    const flows = this.homey.flow;
    const t = (id) => flows.getDeviceTriggerCard(id);

    this.triggers = {
      problemStarted: t('problem_started'),
      problemCleared: t('problem_cleared'),
      wanDown: t('wan_down'),
      wanUp: t('wan_up'),
      serviceStopped: t('service_stopped'),
      serviceStarted: t('service_started'),
      unreachable: t('unreachable'),
      reachable: t('reachable'),
      rebooted: t('rebooted'),
    };

    flows.getConditionCard('is_healthy')
      .registerRunListener(({ device }) => device.getCapabilityValue('alarm_generic') !== true);
    flows.getConditionCard('wan_online')
      .registerRunListener(({ device }) => device.getCapabilityValue('opn_wan_online') === true);

    const serviceAutocomplete = (query, { device }) => device.serviceChoices(query);

    flows.getConditionCard('service_running')
      .registerRunListener(({ device, service }) => device.isServiceRunning(service.id))
      .registerArgumentAutocompleteListener('service', serviceAutocomplete);
    flows.getActionCard('restart_service')
      .registerRunListener(({ device, service }) => device.restartService(service.id))
      .registerArgumentAutocompleteListener('service', serviceAutocomplete);
    flows.getActionCard('refresh')
      .registerRunListener(({ device }) => device.poll());
  }

  /** Readable error for the pairing view. */
  _explain(err) {
    if (err.auth) return this.homey.__('pair.error_auth');
    if (err.cert) return this.homey.__('pair.error_cert', { message: err.message });
    if (err.network) return this.homey.__('pair.error_network', { message: err.message });
    return err.message;
  }

  /**
   * Shared by pairing and repair.
   * probe   -> certificate details so the user can decide to trust it
   * connect -> tests the API with the pinned fingerprint, reports missing privileges
   */
  _connectHandlers(session, onConnected) {
    session.setHandler('probe', async ({ url }) => {
      try {
        return await OPNsenseClient.probeCertificate(url);
      } catch (err) {
        throw new Error(this._explain(err));
      }
    });

    session.setHandler('connect', async ({
      url, key, secret, fingerprint,
    }) => {
      const creds = {
        url: String(url || '').trim().replace(/\/+$/, ''),
        key: String(key || '').trim(),
        secret: String(secret || '').trim(),
        fingerprint: fingerprint || '',
      };
      const client = new OPNsenseClient({ ...creds, log: (...a) => this.log(...a) });
      let snap;
      try {
        snap = await client.snapshot();
      } catch (err) {
        throw new Error(this._explain(err));
      }
      if (snap.forbidden.length === Object.keys(PRIVILEGES).length) {
        throw new Error(this.homey.__('pair.error_no_privileges'));
      }
      const missing = [...new Set(snap.forbidden.map((k) => PRIVILEGES[k]))];
      const { hostname, version } = parseVersion(snap.raw.info);
      const result = {
        creds, hostname: hostname || client.host, version, missing,
      };
      await onConnected(result);
      return { hostname: result.hostname, version, missing };
    });
  }

  async onPair(session) {
    let connected = null;
    this._connectHandlers(session, async (r) => { connected = r; });

    session.setHandler('list_devices', async () => {
      if (!connected) throw new Error(this.homey.__('pair.not_connected'));
      const { creds, hostname, version } = connected;
      const { host, port } = new OPNsenseClient(creds);
      return [{
        name: hostname,
        data: { id: `opnsense-${host}:${port}` },
        store: creds,
        settings: {
          hostname, version, url: creds.url, fingerprint: creds.fingerprint || this.homey.__('settings.ca_verified'),
        },
      }];
    });
  }

  async onRepair(session, device) {
    this._connectHandlers(session, async ({ creds }) => {
      await device.updateConnection(creds);
    });
    session.setHandler('current', async () => ({ url: device.getStoreValue('url') || '' }));
  }
}

module.exports = FirewallDriver;
