'use strict';

const Homey = require('homey');

class OPNsenseApp extends Homey.App {
  async onInit() {
    this.log('OPNsense app started');
  }

  /** Debounced realtime push to the dashboard widget. */
  notifyWidgets() {
    if (this._notifyTimer) return;
    this._notifyTimer = this.homey.setTimeout(() => {
      this._notifyTimer = null;
      this.homey.api.realtime('opnsense:update', { at: Date.now() }).catch(() => {});
    }, 1000);
  }

  /**
   * Data for the health widget.
   * @param {string[]} [ids] Homey device ids picked in the widget; empty = first firewall
   */
  getWidgetData(ids = []) {
    const all = this.homey.drivers.getDriver('firewall').getDevices();
    let device = all[0];
    if (ids.length) {
      const wanted = new Set(ids);
      device = all.find((d) => wanted.has(d.getId()) || wanted.has(d.getAppId())) || device;
    }
    return {
      now: Date.now(),
      timezone: this.homey.clock.getTimezone(),
      language: this.homey.i18n.getLanguage(),
      firewall: device ? device.getWidgetSnapshot() : null,
    };
  }
}

module.exports = OPNsenseApp;
