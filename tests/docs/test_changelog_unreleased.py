"""CHANGELOG.md [Unreleased] must name what an upgrade changes for clients.

Each test pins both halves: the code facts a release note states (read from
the source, so a later change to a limit, an allowlist or a status fails
here until the note follows), and the note itself.  They cover changes that
make requests the 0.1.0 release accepted fail after an upgrade, or change
what an existing credential or button does:

- the gateway's Content-Security-Policy (no inline script, which an
  operator's own template changes may have relied on), how the compose
  stack sets its mode, and the standalone bridge's, which now matches it;
- the bridge admin node routes (allowlist, 404, 429, lease) and the admin
  panel's Restart and Diag buttons;
- the gateway's user API (422 for refused fields and roles, character
  counts, reuse of the current password);
- the bridge key store (503 and startup refusal when keys.json cannot be
  written, edge-prefixed keys as node keys) and the bridge's newer-schema
  refusal;
- the gateway's login and MFA verify (415 for a body not declared JSON),
  logout's cookies, the proxy's session Set-Cookie filter, and both
  services' production refusal of ``BRIDGE_CSRF`` values that turn CSRF
  protection off;
- the bridge's detection-config value rules (422 for wrong types, ranges
  and unknown keys; bundle import checks the same).
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GATEWAY_AUTH = ROOT / "src/gateway/crates/sigrift-gateway-core/src/auth"


def flat(text: str) -> str:
    """*text* with every run of whitespace (line wraps) made one space."""
    return " ".join(text.split())


def unreleased() -> str:
    """The [Unreleased] section of CHANGELOG.md, flattened."""
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    section = text.split("\n## [Unreleased]\n", 1)[1].split("\n## [", 1)[0]
    return flat(section)


def source(path: str | Path) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def match(pattern: str, text: str) -> str:
    """The first group of *pattern* in *text* (multi-line); fails if absent."""
    found = re.search(pattern, text, re.M | re.S)
    assert found, pattern
    return found[1]


def code_list(items: list[str], last: str = "and") -> str:
    """`a`, `b` and `c`, as the notes list code names."""
    quoted = [f"`{item}`" for item in items]
    return ", ".join(quoted[:-1]) + f" {last} {quoted[-1]}"


def missing(needles: list[str], text: str) -> list[str]:
    return [needle for needle in needles if needle not in text]


def test_notes_cover_the_admin_node_command_routes_and_buttons():
    """The admin node routes and buttons changed beyond capture_start/stop.

    At 0.1.0 ``POST /api/admin/nodes/{id}/command`` queued any command name
    for any node id, and it and ``PUT /api/admin/nodes/{id}/config`` queued
    without a cap or a lease. They now share the node router's allowlist,
    404, 429 and lease, so tooling that queued its own names, or queued for
    a node that was offline for longer than the lease, behaves differently.
    The panel's Restart button went from a no-op (``restart_scanner``) to
    restarting every node service, the agent included.
    """
    nodes = source("src/sigrift/bridge/routers/nodes.py")
    lease = match(r"^_COMMAND_LEASE_MINUTES = (\d+)$", nodes)
    cap = match(r"^_MAX_PENDING_COMMANDS_PER_NODE = (\d+)$", nodes)
    allowlist = match(
        r"^ALLOWED_COMMANDS = frozenset\(\s*\{(.*?)\}\s*\)",
        source("src/sigrift/lib/shiny/models.py"),
    )
    commands = re.findall(r'"(\w+)"', allowlist)
    assert commands, allowlist

    admin = source("src/sigrift/bridge/routers/admin.py")
    assert "NodeCommandRequest = CommandRequest" in admin
    # Both admin routes go through the node router's guards and queueing.
    assert admin.count("_queue_for_registered_node(request, node_id,") == 2
    assert "_check_command_queue(request, app_state, node_id)" in admin
    assert "_enqueue_command(app_state, node_id, command, params" in admin

    panel = source("src/sigrift/bridge/static/admin.js")
    assert 'command: "restart", params: {}' in panel
    assert "restart_scanner" not in panel and "run_diagnostics" not in panel
    # The Restart confirmation states the lease the bridge applies.
    assert f"within {lease} minutes" in panel
    # `restart` restarts every service the agent manages, itself included.
    agent = source("src/sigrift/edge/node_agent.py")
    assert '"mlrf-agent"' in match(r"^_SERVICES = \[(.*?)\]$", agent)

    notes = unreleased()
    assert f"The accepted commands are {code_list(commands)}" in notes
    gaps = missing(
        [
            "`POST /api/admin/nodes/{id}/command` took any command name for "
            "any node id",
            "`PUT /api/admin/nodes/{id}/config`",
            "a node that is not registered is a 404",
            f"a node with {cap} commands already pending is a 429",
            "`restart_scanner` and `run_diagnostics`",
            f"not collected within {lease} minutes is dropped",
            "drops the commands still queued for it",
            "**Restart** button sent `restart_scanner`",
            "It now sends `restart`",
            "and then the node agent itself (`mlrf-agent`)",
            "**Diag** queued `run_diagnostics`",
        ],
        notes,
    )
    assert not gaps, gaps


def test_notes_cover_the_gateway_user_api_contract():
    """The gateway's user API refuses requests the 0.1.0 gateway accepted.

    ``POST /api/admin/users`` and ``PUT /api/admin/users/{username}`` now
    answer 422 for an unknown role (400 before), the machine roles,
    usernames outside the bridge's rule (and "." / ".."), and over-long
    profile fields; password limits count characters; change-password
    refuses the current password, and a forced change does so even with
    ``UC_PASSWORD_HISTORY_COUNT=0``.
    """
    users = (GATEWAY_AUTH / "admin_user_handler.rs").read_text(encoding="utf-8")
    username_max = match(r"^const USERNAME_MAX_CHARS: usize = (\d+);$", users)
    display_max = match(r"^const DISPLAY_NAME_MAX_CHARS: usize = (\d+);$", users)
    email_max = match(r"^const EMAIL_MAX_CHARS: usize = (\d+);$", users)
    assert 'Err(_) => Err(unprocessable("Invalid role"))' in users
    assert "Role::Sensor | Role::Node" in users
    assert 'matches!(name, "." | "..")' in users

    password = (GATEWAY_AUTH / "password.rs").read_text(encoding="utf-8")
    assert "let length = password.chars().count();" in password
    min_len = match(r"if length < (\d+) \{", password)
    max_len = match(r"if length > (\d+) \{", password)

    session = (GATEWAY_AUTH / "session_handler.rs").read_text(encoding="utf-8")
    reuse = "Password has been used recently. Choose a different password."
    assert f'"detail": "{reuse}"' in session

    notes = unreleased()
    gaps = missing(
        [
            "`POST /api/admin/users` and `PUT /api/admin/users/{username}`",
            "An unknown role is now a 422 `Invalid role` (it was a 400)",
            "the machine roles `sensor` and `node`, in any spelling",
            f"not 1 to {username_max} characters from `A-Z`, `a-z`, `0-9`, "
            "`_`, `-` and `.`, or that is `.` or `..`",
            f"a `display_name` over {display_max} or an `email` over "
            f"{email_max} characters",
            f"its {min_len} and {max_len} character limits now count "
            "characters, not UTF-8 bytes",
            f"refused with 400 `{reuse}`",
            "on a forced change even when it is 0",
        ],
        notes,
    )
    assert not gaps, gaps


def test_notes_cover_the_strict_script_csp():
    """The gateway's policy refuses inline script; 0.1.0 allowed it.

    A template an operator changed to add an inline ``<script>`` block, an
    ``on…=`` attribute or a ``javascript:`` URL stops working, and the
    escape hatches (``UC_CSP_MODE``) only weaken the policy; the compose
    stack now passes ``UC_CSP_MODE`` from ``.env``, where it was ignored.
    The bridge without a gateway now sends the same policy, which adds the
    directives it lacked, and no longer serves FastAPI's ``/docs`` and
    ``/redoc``. This gateway in front of an older bridge breaks that
    bridge's inline handlers.
    """
    security = source(
        "src/gateway/crates/sigrift-gateway-core/src/middleware/security.rs"
    )
    policy = flat(
        match(r'^const CSP_DIRECTIVES: &str = "\\\n(.*?)";$', security).replace(
            "\\\n", ""
        )
    )
    directives = {d.split()[0]: d.split()[1:] for d in policy.split(";") if d.split()}
    # The note lists what changed for scripts; no other directive (such as
    # script-src-attr, which would take precedence for handler attributes)
    # may change what it says.
    assert list(directives) == [
        "default-src",
        "script-src",
        "object-src",
        "style-src",
        "img-src",
        "connect-src",
        "font-src",
        "frame-ancestors",
        "base-uri",
        "form-action",
    ]
    assert directives["script-src"] == ["'self'"]
    assert directives["object-src"] == ["'none'"]
    assert directives["style-src"] == ["'self'", "'unsafe-inline'"]
    assert '"report-only" => Self::ReportOnly' in security
    assert '"disabled" => Self::Disabled' in security
    assert '"content-security-policy-report-only"' in security
    config = source("src/gateway/crates/sigrift-gateway-core/src/config.rs")
    assert 'env = "UC_CSP_MODE"' in config
    bridge = source("src/sigrift/bridge/app.py")
    bridge_policy = "".join(
        re.findall(r'"([^"]*)"', match(r"^_CSP_VALUE = \((.*?)\)$", bridge))
    ).strip()
    assert bridge_policy == policy
    for name in ("base-uri", "form-action", "font-src"):
        assert name in directives, name
    assert (
        '_PERMISSIONS_POLICY = "camera=(), microphone=(), geolocation=(), payment=()"'
        in bridge
    )
    application = match(r"^(app = FastAPI\(.*?^\))$", bridge)
    assert "docs_url=None," in application and "redoc_url=None," in application
    # The compose files pass the mode from .env; no default would reach
    # the gateway as an empty value, which clap refuses.
    for compose in ("docker-compose.yml", "scripts/install-release.sh"):
        gateway = match(r"^  gateway:\n(.*?)\n  [a-z]", source(compose))
        assert re.search(r"- UC_CSP_MODE=\\?\$\{UC_CSP_MODE:-strict\}$", gateway, re.M)
    # The older templates' inline handlers, which this gateway refuses.
    template = source("src/sigrift/bridge/templates/index.html")
    assert "onclick=" not in template and 'id="sg-export-png"' in template

    notes = unreleased()
    gaps = missing(
        [
            "It now sends `script-src 'self'` (no `'unsafe-inline'`, no "
            "`'unsafe-hashes'`) and `object-src 'none'`; styles still allow "
            "`'unsafe-inline'`",
            "an inline `<script>` block, an event-handler attribute "
            "(`onclick=`, `onload=`, ...) or a `javascript:` URL now does "
            "nothing there",
            "`UC_CSP_MODE=report-only` sends the policy as "
            "`Content-Security-Policy-Report-Only`",
            "`UC_CSP_MODE=disabled` sends no policy",
            "A bridge run without a gateway now sends the same policy, which "
            "adds `base-uri 'self'`, `form-action 'self'` and `font-src "
            "'self'` to its own",
            "and `payment=()` to its `Permissions-Policy`",
            "the gateway now takes `UC_CSP_MODE` from `.env`, `strict` when "
            "unset; before, a value set there never reached it",
            "add `- UC_CSP_MODE=${UC_CSP_MODE:-strict}` to its gateway's "
            "`environment:`",
            "this gateway in front of an older bridge refuses that bridge's "
            'inline handlers, so its documentation ("?") menu and Export PNG '
            "button do nothing; an older gateway in front of this bridge is "
            "fine",
            "The bridge no longer serves FastAPI's generated `/docs` (Swagger "
            "UI) and `/redoc` pages, now 404",
            "`/openapi.json` is unchanged",
        ],
        notes,
    )
    assert not gaps, gaps


def test_notes_cover_key_store_writes_edge_key_roles_and_newer_schemas():
    """Bridge changes that refuse startup, answer 503 or lower a key's role.

    A key change keys.json cannot record answers 503 (it used to succeed in
    one worker's memory) and startup refuses when it must write a key; a
    key whose id has an edge prefix and any operator role in any letter
    case is a node key (0.1.0 lowered only exact ``admin`` / ``analyst``);
    and the bridge refuses a database a newer bridge migrated.
    """
    not_saved = match(
        r'^KEY_CHANGE_NOT_SAVED = "([^"]+)"$', source("src/sigrift/bridge/utils.py")
    )
    persistence = source("src/sigrift/bridge/persistence.py")
    prefixes = re.findall(
        r'"(\w+)"', match(r"^_EDGE_PREFIXES = \((.*?)\)$", persistence)
    )
    assert prefixes
    assert "_role_rank(role) >= _ANALYST_RANK" in persistence
    # The note says the gateway applies the same rule.
    api_key = (GATEWAY_AUTH / "api_key.rs").read_text(encoding="utf-8")
    gateway_prefixes = match(
        r"^pub const EDGE_KEY_PREFIXES: \[&str; \d+\] =\s*\[(.*?)\];", api_key
    )
    assert re.findall(r'"(\w+)"', gateway_prefixes) == prefixes
    assert "if edge_key && role >= Role::Analyst {" in api_key
    app = source("src/sigrift/bridge/app.py")
    assert (
        '"Refusing to start: %s must be saved to %s, which cannot be written "' in app
    )
    base = source("src/sigrift/bridge/storage/base.py")
    assert "_refuse_newer_schema(conn)" in base
    assert "newer than this build" in base

    notes = unreleased()
    stems = "|".join(p.rstrip("_") for p in prefixes)
    gaps = missing(
        [
            f"503 `{not_saved}`",
            "the bridge refuses to start when it must save the initial master "
            "key, re-sync `BRIDGE_MASTER_KEY` or register "
            "`BRIDGE_LOCAL_NODE_KEY`",
            f"A key whose id starts with {code_list(prefixes, 'or')}",
            "`analyst`, `admin` or `keymaster` in any letter case",
            "`PUT /api/admin/keys/{key_id}/permissions` refuses an operator "
            "role for such a key with 400",
            f'test("^({stems})_")',
            "Bridge: it now refuses to start on a database that a newer "
            "bridge has migrated (PRE-68)",
        ],
        notes,
    )
    assert not gaps, gaps


def test_notes_cover_login_content_type_logout_cookies_and_csrf_setting():
    """Stage 0 of the cookie-only plan: what clients and operators see.

    The 0.1.0 gateway read any login or MFA verify body as JSON (login
    CSRF), answered a stale-cookie logout with 401 and no cookie, relayed
    any backend ``Set-Cookie``, and honoured ``BRIDGE_CSRF=disabled`` in
    production; the bridge turned CSRF off for any value but ``enabled``.
    A logout 401 expires the cookies only when the request carried one
    (a cross-site form post carries none: forced sign-out), and the SSO
    routes under ``/api/oidc`` may still set the session cookie.
    """
    session = (GATEWAY_AUTH / "session_handler.rs").read_text(encoding="utf-8")
    detail = match(r'"detail": "(Content-Type must be [^"]+)"', session)
    assert detail == "Content-Type must be application/json"
    assert "StatusCode::UNSUPPORTED_MEDIA_TYPE" in session
    assert 'essence.trim().eq_ignore_ascii_case("application/json")' in session
    assert "(Some(value), None) =>" in session  # exactly one Content-Type
    login = match(r"(pub async fn login\(.*?let conn = )", session)
    assert "if !declares_json_body(req.headers())" in login
    mfa = (GATEWAY_AUTH / "mfa_handler.rs").read_text(encoding="utf-8")
    verify = match(r"(pub async fn mfa_verify_login\(.*?let client = )", mfa)
    assert "if !declares_json_body(req.headers())" in verify

    logout = match(r"(pub async fn logout\(.*?\n\}\n)", session)
    # The 5xx outcomes return before the cookies are appended.
    assert "Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response()," in logout
    assert "return StatusCode::INTERNAL_SERVER_ERROR.into_response();" in logout
    cookies = logout.split("let mut resp = (status, Json(body)).into_response();")[1]
    assert (
        "if status == StatusCode::OK || carries_a_logout_cookie(&headers) {" in cookies
    )
    assert ".map(|name| expire_cookie(name, is_secure))" in cookies
    expired = match(r"const LOGOUT_COOKIES: \[&str; 3\] = \[(.*?)\];", session)
    for name in ["SESSION_COOKIE", '"csrf_token"', "LEGACY_TOKEN_COOKIE"]:
        assert name in expired
    routers = source("src/sigrift/bridge/routers/auth.py")
    signed_out = match(r"(def signed_out\(.*?return response)", routers)
    assert "if status_code == status.HTTP_200_OK or any(" in signed_out
    assert "name in request.cookies for name in _LOGOUT_COOKIES" in signed_out
    assert "_expire_csrf_cookie(request, response)" in signed_out
    assert '_LOGOUT_COOKIES = ("session_token", "csrf_token")' in routers

    proxy = source("src/gateway/crates/sigrift-gateway-core/src/proxy/handler.rs")
    assert (
        "if name == header::SET_COOKIE && !relays_backend_cookie(path, value)" in proxy
    )
    sso = match(r'^const SSO_PATH: &str = "([^"]+)";$', proxy)
    assert sso == "/api/oidc"
    assert (
        "Some(cookie) => cookie == crate::middleware::auth::SESSION_COOKIE "
        "&& is_sso_path(path)," in flat(proxy)
    )

    refusal = "unset BRIDGE_CSRF or set it to enabled"
    builder = source("src/gateway/crates/sigrift-gateway-core/src/builder.rs")
    assert 'normalized.is_empty() || normalized == "enabled"' in builder
    assert refusal in flat(builder.replace("\\\n", " "))
    app = source("src/sigrift/bridge/app.py")
    assert 'if _csrf_setting() in ("", "enabled"):' in app
    assert refusal in app
    assert 'os.environ.get("BRIDGE_CSRF", "").strip().lower()' in app

    notes = unreleased()
    gaps = missing(
        [
            "`POST /api/auth/login` and `POST /api/auth/mfa/verify` now answer "
            f'415 `{{"detail": "{detail}"}}`',
            "a missing `Content-Type`, two of them, "
            "`text/plain;charset=application/json` and `+json` types are refused",
            "a script that posts the JSON without the header must now add it",
            "expires `session_token`, `csrf_token` and `bridge_token` on a 401 "
            "(no session token, or one that names no session) when the request "
            "carried one of those cookies",
            "A 401 for a request that carried none of them still sets no cookie: "
            "a cross-site form post carries none",
            "A 500 or 503 still sets no cookie",
            "The bridge's logout now expires `csrf_token` on 200, and on 401 when "
            "the request carried `session_token` or `csrf_token`",
            "**The gateway no longer relays a backend `Set-Cookie` for "
            "`session_token` or `bridge_token`**, except `session_token` from the "
            f"SSO routes under `{sso}`.",
            f"so that one cookie is still relayed from `{sso}` and the paths "
            "below it (the path as sent, case-sensitive, not percent-decoded)",
            "**`sigrift-sentinel` SSO behind the gateway:**",
            "**Scripts that sign in must send `Content-Type: application/json`.**",
            "The most common way to hit it is `curl -d` without `-H`",
            "Add `-H 'Content-Type: application/json'`",
            "the bridge turns its check off for every such value, the gateway "
            "only for exactly `disabled`",
            "**Production refuses to start with CSRF protection turned off.**",
            f'"{refusal}"',
            "(`off`, `true`, `0`, ` enabled`), so all of them are refused",
            '`PUT /api/admin/settings/security` `{"csrf_enabled": false}`',
            "Gateway: login CSRF.",
            "(`constant_time_eq`, `hmac.compare_digest`)",
            "a 401 logged the first 8 characters of the session token",
        ],
        notes,
    )
    assert not gaps, gaps


def test_notes_cover_the_detection_config_value_rules():
    """``PUT /api/admin/detection-config`` refuses values 0.1.0 stored.

    Every value is checked (types, ranges, unknown keys) and a refused
    request is a 422; bundle import applies the same rules.
    """
    rules = source("src/sigrift/bridge/detection_config.py")
    max_count = int(match(r"^_MAX_COUNT = ([\d_]+)$", rules).replace("_", ""))
    hours = match(r"^_MAX_HOURS = ([\d *]+)$", rules).split("*")
    max_hours = 1
    for factor in hours:
        max_hours *= int(factor)
    entries = match(r"^_MAX_ENTRIES = (\d+)$", rules)
    weight_sum = match(r"^_MAX_WEIGHT_SUM = ([\d.]+)$", rules)
    router = source("src/sigrift/bridge/routers/system_config.py")
    assert "body = check_detection_config(body, old_config)" in router
    assert router.count("raise HTTPException(status_code=422, detail=str(exc))") == 2
    bundles = source("src/sigrift/bridge/bundles.py")
    assert bundles.count("check_detection_config(") == 2
    assert '"strict": True' in rules

    notes = unreleased()
    gaps = missing(
        [
            "`PUT /api/admin/detection-config` stored any value it was sent",
            "a request with a refused value is a 422 whose string `detail` "
            "names each problem (a body that is not a JSON object gets "
            "FastAPI's usual 422, whose `detail` is a list)",
            "Thresholds, scores and `rf_min_confidence_floor` must be numbers "
            "from 0 to 1",
            f"whole numbers from 0 to {max_count}",
            f"the snooze hours whole numbers from 0 to {max_hours}",
            f"A weight object and `protocol_detection` hold at most {entries} "
            "entries, counted as stored",
            f"sum to at most {weight_sum}, as bundle validation already required",
            "A key the bridge does not know is refused",
            "a client that sent a number as a string, or a key of its own, "
            "now gets a 422",
            "A partial `protocol_detection` now merges into the stored toggles",
            "Bundle import and preset apply check a bundle's `detection_config`",
            "is refused (422) before any of its components is applied",
        ],
        notes,
    )
    assert not gaps, gaps


def test_notes_cover_stored_detection_config_values_and_strict_toggles():
    """Stored values the rules refuse are left out on read, logged by name.

    ``PUT /api/admin/protocols`` and ``POST /api/admin/auto-rescan`` no
    longer convert strings (``"false"`` turned a protocol on).
    """
    persistence = source("src/sigrift/bridge/persistence.py")
    assert "usable_detection_config(_safe_load(path)" in persistence
    warning = "stored values the configuration rules refuse are left out"
    assert f'"%s: {warning} "' in persistence
    router = source("src/sigrift/bridge/routers/system_config.py")
    protocols = router.split('@router.put("/protocols")', 1)[1].split("@router", 1)[0]
    assert "check_detection_config(" in protocols and "bool(" not in protocols

    notes = unreleased()
    gaps = missing(
        [
            "Such a value is now left out when the configuration is read, so "
            "its default applies",
            "the bridge logs a warning naming each one, and the next write "
            "drops them from `detection_config.json`",
            "**Detection-config values a 0.1.0 bridge stored may stop applying.**",
            f"look for the WARN `detection_config.json: {warning}`",
            "`PUT /api/admin/protocols` turned a protocol on for any value "
            'Python counts as true, the string `"false"` included',
            "a name the bridge does not list is still ignored",
            "They are now strict: such a value is a 422, not converted.",
        ],
        notes,
    )
    assert not gaps, gaps
