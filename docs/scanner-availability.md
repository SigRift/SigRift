# Live scanner availability

The dashboard distinguishes an online edge monitor from an actively capturing
scanner. A generic heartbeat, configured USB device, historical detection, or
requested anomaly setting does not enable a scanner tab.

A registered worker reports its actual capture state with its node-bound API key:

```text
POST /api/nodes/{node_id}/scanner-status
{"protocol":"wifi","state":"running"}
```

The authenticated route accepts SENSOR/NODE credentials bound to that node and
existing authorized operator credentials. A credential for another node is
refused. Protocols are `sdr`, `wifi`, `bluetooth`, `zigbee`, and `adsb`; states are
`running`, `stopped`, and `error`. Client timestamps, expiry settings, and extra
fields are refused. Reports use server time and expire after 120 seconds.
An `error` report may add one fixed `reason`: `starting`, `sensor_absent`,
`sensor_changed`, `sensor_unusable` (attached and the right sensor, but the host
does not let the scanner open it), or `capture_failed`, for example
`{"protocol":"sdr","state":"error","reason":"sensor_absent"}`. A reason with
any other state, or any other value, is refused. See
[sensor-lifecycle.md](sensor-lifecycle.md) for what each one means.
Workers should report at least every 30 seconds; stopped/error reports invalidate
availability immediately. A lost network connection leaves a short expiry grace
instead of making navigation flicker on every failed request.

Node responses include `scanner_status`, with each report's `protocol`, `state`,
`reason` (null when there is none or the report has expired), `reported_at`,
`expires_in_seconds`, and `active`. Reports persist with node data
but restart does not renew their timestamps. Ordinary heartbeat metrics cannot
forge or renew these records. Status WebSocket updates and ten-second node
polling refresh the dashboard; a browser also expires its last lease locally if
both connections fail. Duplicate or older snapshots cannot extend a lease.

An SDR lease enables RF Intelligence, Spectrum Analysis, Drone, and IoT views,
which consume RF classifications. Wi-Fi, Bluetooth, Zigbee, and ADS-B each require
their own lease. Unavailable tabs start hidden, remain disabled, and cannot be
opened by saved-tab preferences, keyboard navigation, or drill-down links. If an
active scanner disappears, the dashboard returns to Summary and stops that
view's polling. Historical records remain in storage and accessible through the
existing authorized summary/API paths. Core dashboard and administration views
remain available.

RF and Wi-Fi producers are the initial integrations. RF reports readiness only
after successful capture and classification; Wi-Fi requires a valid radiotap
stream, live capture/read loop, and recent successful channel selection. Quiet
Wi-Fi air is not an error. Bluetooth, Zigbee, and ADS-B stay hidden until an
actual producer implements the same capture-health contract; device inventory
alone must not manufacture those reports. Existing workers require an upgrade
before their scanner tabs can appear.

Disposable browser tests explicitly issue synthetic lifecycle reports through
the real gateway, then stop them and revoke their key. Those tests establish
software delivery, authentication, visibility, and cleanup, not physical radio
capture. Hardware discovery and guided setup are a separate workflow.
