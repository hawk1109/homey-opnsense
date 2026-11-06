'use strict';

module.exports = {
  async getData({ homey, query }) {
    const ids = String(query.ids || '').split(',').map((s) => s.trim()).filter(Boolean);
    return homey.app.getWidgetData(ids);
  },
};
