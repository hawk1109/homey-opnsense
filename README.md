# OPNsense for Homey

Homey (SDK v3) app that turns an **OPNsense** firewall into a Homey device with a
health dashboard widget: internet quality, services, system resources and events.
Same structure as [homey-ojmicroline](https://github.com/hawk1109/homey-ojmicroline).

## Features

| Capability | Source |
|---|---|
| `alarm_generic` / `opn_status` | any problem from the checks below; status text lists them |
| `opn_wan_online` | gateway status (dpinger `down` / `force_down` = offline) |
| `opn_wan_latency` / `opn_wan_loss` | gateway monitor (needs a *Monitor IP* on the gateway) |
| `opn_wan_download` / `opn_wan_upload` | byte-counter delta on the WAN interface between polls |
| `opn_load` | 5-minute load average |
| `opn_memory`, `measure_temperature`, `opn_disk` | Lobby dashboard data (highest sensor, root filesystem) |
| `opn_states` | pf state table size |
| `opn_services_down` | stopped services, minus *Ignore services* |
| `opn_if_errors` | new rx/tx errors + drops on **assigned** interfaces in the last hour |
| `opn_uptime` | system uptime |

Thresholds for every check are device settings.

**Flow cards**

- Triggers: problem started / resolved (with duration) · internet down / back · service stopped / started · firewall unreachable / reachable again · firewall rebooted
- Conditions: is healthy · internet is up · service is running
- Actions: restart a service · refresh now

**Dashboard widget, *Firewall health*:** status with active problems, WAN latency as the hero
figure, loss and live throughput, 24-hour latency and throughput charts (5-minute buckets,
outages shaded, hover for values), resource tiles with threshold colours, services (stopped first,
running ones collapsed) and recent events. Updates are pushed on every poll (`opnsense:update`)
with a 60 s fallback.

## Setup on the firewall

1. **System → Access → Users → Add**: a user such as `homey`, no shell, a long random password you never use.
2. Under **Effective privileges**, add:

   | Privilege | Gives Homey | Note |
   |---|---|---|
   | `Lobby: Dashboard` | uptime, load, memory, temperature, disk, states, version | read-only |
   | `System: Gateways` | WAN status, latency, loss | also grants gateway *settings* API |
   | `Status: Services` | service list, *restart a service* card | also grants start/stop |
   | `Diagnostics: Netstat` | throughput, interface errors | read-only |

   Mapping verified against `opnsense/core` `ACL.xml`. Leave out any you don't want; the app shows
   what is missing under *Missing privileges* in the device settings and leaves those values empty.
3. Edit the user → **API keys → +**. A file with `key=` and `secret=` downloads.
4. **System → Gateways**: give the WAN gateway a *Monitor IP* (e.g. `1.1.1.1`) and leave
   monitoring enabled, otherwise latency and loss stay empty.

## Pairing and the certificate

Add device → OPNsense → enter `https://<firewall>`, key and secret → *Check certificate*.
A home firewall has a self-signed or private-CA certificate, so the app shows its SHA-256
fingerprint. Compare it with **System → Trust → Certificates** and choose *Trust*.

The fingerprint is **pinned**: the app opens the TLS connection, checks the fingerprint and only
then sends the request with the API key. A different certificate (or a machine pretending to be
the firewall) never receives the key. When you renew the firewall certificate the device becomes
unavailable with *certificate has changed*; use **Repair** to trust the new one.
A certificate that is publicly trusted (e.g. ACME) is verified normally instead of pinned.

## Architecture

```
app.js                      widget data + debounced realtime push
lib/OPNsenseClient.js       API client: key/secret basic auth, fingerprint pinning, per-endpoint 403 handling
lib/health.js               pure parsing + threshold evaluation (unit tested on live fixtures)
drivers/firewall/driver.js  pairing / repair (probe → trust → connect), flow card wiring
drivers/firewall/device.js  polling, state machine (problems, transitions, unreachable), 24 h history
widgets/health/             dashboard widget (public/index.html, api.js → app.getWidgetData)
```

- One poll = 9 GETs, sequential, every 60 s by default (min 30 s).
- Two consecutive failed polls = *unreachable*; a single blip is ignored.
- History: 288 five-minute buckets (max latency/loss, mean throughput, outage flag), persisted every 15 min.
- No code or configuration is added to the firewall, so the app survives OPNsense updates
  and moves to new hardware by repairing the address.

## Develop

```bash
npm i -g homey
npm test                              # 29 tests: parsers on live fixtures, TLS pinning, device state machine
homey login && homey select
homey app run                         # live-run with logs
homey app install                     # install permanently
homey app validate --level publish
```
