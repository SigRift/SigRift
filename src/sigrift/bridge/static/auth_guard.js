/* Auth guard — set the dashboard's credentials globally for dashboard.js.
 *
 * The session token comes from sessionStorage (login.js stores the one the
 * login response returns).  The session cookie the gateway sets is
 * HttpOnly, so it is never read here: when there is no stored token but a
 * CSRF cookie exists, the dashboard runs in cookie mode — credentialed
 * fetches and WebSockets authenticated by that cookie.  (Older gateways
 * also set a JS-readable `bridge_token` copy of the session token; it is
 * deliberately ignored.)
 */
(function() {
    var ct = (document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/) || [])[1] || "";
    var ss = "";
    try { ss = sessionStorage.getItem("bridge_session_token") || ""; } catch(e) {}
    if (ss === "undefined" || ss === "null") ss = "";

    /* Always set globally — dashboard.js reads this */
    window.__bridge_auth = { sessionToken: ss, csrfToken: ct, apiKey: "" };

    /* Only redirect if truly no auth at all */
    var key = "";
    try { key = sessionStorage.getItem("bridge_api_key") || ""; } catch(e) {}
    if (!ss && !ct && !key) {
        window.location.replace("/login?next=" + encodeURIComponent(window.location.pathname));
    }
})();

/* CSRF helper */
function _getCsrfToken() {
    return (document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/) || [])[1] || "";
}

/* Auto-attach CSRF token to mutating requests */
(function() {
    var _orig = window.fetch;
    window.fetch = function(url, opts) {
        opts = opts || {};
        var m = (opts.method || "GET").toUpperCase();
        if (m === "POST" || m === "PUT" || m === "DELETE" || m === "PATCH") {
            var csrf = _getCsrfToken();
            if (csrf) {
                opts.headers = opts.headers || {};
                if (opts.headers instanceof Headers) {
                    if (!opts.headers.has("X-CSRF-Token")) opts.headers.set("X-CSRF-Token", csrf);
                } else {
                    if (!opts.headers["X-CSRF-Token"]) opts.headers["X-CSRF-Token"] = csrf;
                }
            }
        }
        return _orig.call(this, url, opts);
    };
})();
