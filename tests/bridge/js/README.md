# JavaScript Unit Tests

Tests execute the shipped frontend files inside a small DOM fixture. They do
not copy authentication or CSRF logic into the tests.

The login-controller regression tests execute the shipped `login.js`. The
complete suite also exercises the real V8-to-Istanbul converter, using the
existing locked measurement dependencies with Node.js 22.12 or newer:

```bash
npm ci --prefix tests/bridge/js --ignore-scripts
node --test tests/bridge/js/*.test.cjs
```

They cover the MFA challenge/request contract, TOTP and backup codes,
single-use challenge retries, duplicate submissions, missing challenges,
non-JSON errors, and the actual CSRF fetch wrapper. The mandatory script CI
job runs every `.test.cjs` suite through `scripts/tests/test_login_controller.py`.

## Dashboard rendering of untrusted values

`untrusted_dom.cjs` boots the shipped `auth_guard.js`, `dashboard.js` and
panel scripts in `node:vm` over a small DOM whose `innerHTML` is parsed by
parse5, so escaping is judged by the tree a browser would build. The
`dashboard_security`, `detections_rendering` and `wifi_rendering` suites feed
hostile node, sensor and radio strings through the real fetch and WebSocket
handlers and check that they stay text, that writes carry the CSRF token, and
that expiry and sign-out behave. Each element a test lists is built from
`templates/index.html` when the page defines it (tag, attributes, default
values, and the options a `<select>` offers, which is the only value it can
hold), so tests drive the controls an operator has. A listed id in `subtrees`
also gets its index.html children (a button group or a whole panel), with the
other listed elements moved into their real place. Timers run on a simulated
clock: `f.tick(ms)` lets that much time pass, with no wall-clock waits. Known
defects are `todo` tests whose reason starts with `BUG:`; each passes once its
defect is fixed. `todo` never fails the run, so remove the marker when a fix
lands.

## Admin console

`admin_dom.cjs` opens the whole of `templates/admin.html` with the shipped
`auth_guard.js`, `severity.js`, `html_text.js`, `admin.js` and
`crypto_admin.js`, in page order, over the same kind of parse5-backed DOM.
Requests go to a recording fake network that answers with real `Response`
objects, timers run on a simulated clock (`page.advance(ms)`), and the
floor-plan canvas records its drawing calls. Each suite runs
`test.afterEach(noUnexpectedConsoleErrors)`, so a page that writes to
`console.error` (where `admin.js` sends exceptions it swallows) fails the
test unless the test calls `page.allowConsoleErrors()`. `admin_console_security` checks
escaping, credentials and confirmations; the `admin_*_tab(s)` suites and
`admin_console_shell` drive each tab's forms, tables and dialogs through the
page's own controls. `deployment_fleet_table` runs `deployment.js` in the
dashboard page from `untrusted_dom.cjs`.

`markup_sinks` finds every static page's escaping helper (`esc()` and its
per-page copies, Shiny's included) and requires each to keep text and single-
or double-quoted attribute values literal; a page that escapes by
serialising a text node again, which leaves quotes as they are, fails it.
It then covers each escaped sink of the dashboard's panel scripts: counts
and numbers sent as strings, IDs used to find elements, map popups
(`maps.js`, `geo_map.js`, ADS-B), panels that built rows from raw strings,
and HTML-encoded fields (activity log entries) shown once decoded. The admin page's own scripts (`training.js`,
`protocol_admin.js`, `scorer_weights.js`) are covered in
`admin_console_security`, which loads them with `admin_dom.cjs`'s
`PAGE_SCRIPTS`.

## Full source coverage

Use Node.js 22.12 or newer. The coverage-only dependencies are pinned in the
adjacent npm lockfile; installation does not execute dependency scripts.

The default command is the release gate. It fails closed on any inventory or
counter problem, then requires the aggregate line **and** branch percentages to
be at or above the committed ratchet floor in `scripts/coverage-floors.json`
(exact counter comparison, no rounding). The result is written to
`reports/coverage/javascript/floor.json`. Raise the floor when coverage goes
up; never lower it. Unmeasured inline HTML and unobserved branch ranges are
still recorded in `inventory.json` as known gaps, but no longer fail the gate on
their own.

```bash
npm ci --prefix tests/bridge/js --ignore-scripts
node tests/bridge/js/coverage.cjs

# Explicit measurement without enforcing the floor:
node tests/bridge/js/coverage.cjs --report-only
```

The wrapper uses [c8](https://github.com/bcoe/c8) with `--all`. Its Git inventory
includes authored `.js`, `.mjs`, and `.cjs` files throughout the repository,
including the three Shiny frontend files and new untracked source files.
Unexecuted files remain in the report at zero. The only excluded source file
is vendored `bridge/static/vendor/leaflet.js`. Only the actually collected
`tests/bridge/js/*.test.cjs` test cases are excluded. Executable tools under
test directories, including `coverage.cjs` and the k6 load script, remain
measured source; an arbitrary `.test.cjs` filename elsewhere is not an exception.

HTML templates are inspected for inline scripts, event handlers, and
`javascript:` links. They are recorded as **unmeasured** in the inventory
until their behavior is instrumented; they are not silently omitted. JSON data blocks and external script references
contain no inline executable source to measure.

Machine-readable Istanbul JSON, LCOV, the file inventory, and the summary are
written to `reports/coverage/javascript/`. The command rejects missing files,
unexpected files, empty inventories, and zero-line source records. VM tests
use each shipped file's real path so tooling cannot report an empty file set
as 100% coverage.

## Browser execution coverage

Collect Chromium V8 counts during real E2E flows with an absolute private
output directory. Use the same verified-CA and disposable-stack environment
as the [end-to-end candidate run](../../../CONTRIBUTING.md#end-to-end-candidate-run).

```bash
SIGRIFT_E2E_JS_COVERAGE=/absolute/private/browser-coverage \
  python -m pytest tests/e2e --timeout=120
node tests/bridge/js/coverage.cjs --report-only \
  --browser-coverage=/absolute/private/browser-coverage
```

The collector drains precise counts before navigation and at test teardown.
It accepts only same-origin shipped JavaScript whose bytes match the checked
out source. Reports retain counts, source paths, and source hashes; they do
not retain requests, credentials, storage, or DOM state. The merge validates
those hashes again, so a report from another application build is refused.
Keep browser inputs outside `reports/coverage/javascript`, which the wrapper
regenerates. Inline HTML behavior remains explicitly unmeasured.

An executed function must have explicit precise block-coverage metadata.
Function-only execution cannot establish branch coverage: the real converter
can otherwise mark its lines covered while reporting no branch outcomes.
V8 legitimately reports an unexecuted function with `isBlockCoverage: false`
and zero counts. That evidence stays uncovered and its internal branches stay
unknown. A later block measurement resolves only the same source/function
range. The inventory records unknown functions and unloaded files; either
keeps `inventory.json`'s `complete` flag false even if other counters total 100%.

These are V8/c8 branch metrics, not an upfront enumeration of every JavaScript
conditional. c8 represents never-loaded files with zero-coverage placeholders;
their detailed branch counts grow as tests load and execute them. Compare the
line numerator and per-file gaps alongside branch percentages. Browser E2E
pass counts alone are separate evidence; only validated V8 execution data
contributes to a combined report.

The remaining work includes real dashboard/controller tests, DOM interactions
and failure handling for the admin panels that live outside `admin.js`
(`protocol_admin.js`, `scorer_weights.js`, `training.js`), and Shiny frontend
tests beyond the key panel (`shiny_key_panel.test.cjs`), the write buttons and
forms (`shiny_viewer_writes.test.cjs`: a refused write is reported) and the
spectrum connect / disconnect buttons (`shiny_spectrum_writes.test.cjs`).
Physical capture, decoder accuracy, and deployment behavior require additional
integration evidence regardless of the line and branch numbers.

Note: branch percentages count only loaded files, so loading a new file in a
test can lower the branch percentage while raising lines. Leave headroom in the
branch floor for that.
