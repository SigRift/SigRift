/* Login page controller — external file for CSP compliance */

// Determine post-login redirect from ?next= param (default: /dashboard)
var _nextUrl = "/dashboard";
try {
    var _p = new URLSearchParams(window.location.search).get("next");
    if (_p && _p.startsWith("/") && !_p.startsWith("//")) {
        // URL parsing normalizes backslashes and control whitespace. A raw
        // slash-prefix check alone can redirect a signed-in user off-site.
        var _target = new URL(_p, window.location.origin);
        if (_target.origin === window.location.origin) {
            // Keep the verified absolute URL. A normalized pathname can
            // begin with // (for example /.//host), which location.replace
            // would otherwise parse again as an external network-path URL.
            _nextUrl = _target.href;
        }
    }
} catch(_) {}

// Clear any stale credentials on login page load
sessionStorage.removeItem("bridge_session_token");
sessionStorage.removeItem("bridge_api_key");
sessionStorage.removeItem("bridge_admin_key");

document.addEventListener("DOMContentLoaded", function() {
    var activeTab = "login";
    var mfaTempToken = null;
    var mfaSubmitting = false;
    var passwordChangeCredentials = null;
    var submitBtn = document.getElementById("login-submit");
    var errorEl = document.getElementById("login-error");

    function showError(msg) {
        errorEl.textContent = msg;
        errorEl.style.display = "block";
    }
    function hideError() {
        errorEl.style.display = "none";
        errorEl.textContent = "";
    }
    function showMfa() {
        document.getElementById("mfa-section").style.display = "block";
        submitBtn.style.display = "none";
        document.getElementById("mfa-code").focus();
    }
    function hideMfa() {
        document.getElementById("mfa-section").style.display = "none";
        submitBtn.style.display = "";
        mfaTempToken = null;
        document.getElementById("mfa-code").value = "";
    }
    function setLoading(on) {
        submitBtn.disabled = on;
        submitBtn.textContent = on ? "Signing in..." : "Sign In";
    }

    // Tab switching
    document.querySelectorAll(".login-tab").forEach(function(tab) {
        tab.addEventListener("click", function() {
            activeTab = tab.getAttribute("data-tab");
            document.querySelectorAll(".login-tab").forEach(function(t) { t.classList.remove("active"); });
            tab.classList.add("active");
            document.getElementById("panel-login").classList.toggle("active", activeTab === "login");
            document.getElementById("panel-apikey").classList.toggle("active", activeTab === "apikey");
            hideError();
            hideMfa();
        });
    });

    function submitLogin() {
        var user = document.getElementById("username").value.trim();
        var pass = document.getElementById("password").value;
        if (!user || !pass) { showError("Enter username and password"); return; }
        hideError();
        setLoading(true);

        fetch("/api/auth/login", {
            method: "POST",
            headers: { "Content-Type": "application/json", "Accept": "application/json" },
            body: JSON.stringify({ username: user, password: pass }),
            credentials: "same-origin"
        }).then(function(r) {
            if (!r.ok) {
                // Capture status + Retry-After before consuming the body so we
                // can surface rate-limit detail (auth.py returns 429 with a
                // Retry-After header on both IP-rate-limit and account-lockout).
                var status = r.status;
                var retryAfter = r.headers.get("Retry-After");
                return r.json().catch(function(){ return {}; }).then(function(e) {
                    e = e || {};
                    e.__status = status;
                    e.__retryAfter = retryAfter;
                    return Promise.reject(e);
                });
            }
            return r.json();
        }).then(function(data) {
            if (data.mfa_required) {
                if (typeof data.mfa_token !== "string" || !data.mfa_token) {
                    return Promise.reject({ detail: "MFA challenge missing. Sign in again." });
                }
                mfaTempToken = data.mfa_token;
                showMfa();
                setLoading(false);
                return;
            }
            finishLogin(data, pass);
        }).catch(function(err) {
            showError(formatLoginError(err));
            setLoading(false);
        });
    }

    function formatLoginError(err) {
        if (!err) return "Login failed";
        if (err.__status === 429) {
            var secs = parseInt(err.__retryAfter, 10);
            if (isFinite(secs) && secs > 0) {
                if (secs >= 60) {
                    var mins = Math.ceil(secs / 60);
                    return "Too many login attempts — try again in " + mins + " minute" + (mins === 1 ? "" : "s");
                }
                return "Too many login attempts — try again in " + secs + " second" + (secs === 1 ? "" : "s");
            }
            return err.detail || "Too many login attempts — please wait before trying again";
        }
        return err.detail || "Login failed";
    }

    function submitMfa() {
        if (mfaSubmitting) return;
        if (!mfaTempToken) {
            hideMfa();
            showError("MFA challenge missing. Sign in again.");
            return;
        }
        var code = document.getElementById("mfa-code").value.trim();
        if (!code) { showError("Enter MFA code"); return; }
        hideError();
        mfaSubmitting = true;
        document.getElementById("mfa-submit").disabled = true;

        fetch("/api/auth/mfa/verify", {
            method: "POST",
            headers: { "Content-Type": "application/json", "Accept": "application/json" },
            body: JSON.stringify({ mfa_token: mfaTempToken, totp_code: code }),
            credentials: "same-origin"
        }).then(function(r) {
            if (!r.ok) return r.json().then(function(e) { return Promise.reject(e); });
            return r.json();
        }).then(function(data) {
            mfaTempToken = null;
            finishLogin(data, document.getElementById("password").value);
        }).catch(function(err) {
            // The server consumes the challenge even when the code is wrong.
            // A new password step is required before trying another code.
            hideMfa();
            showError(((err && err.detail) || "MFA verification failed") + ". Sign in again to retry.");
        }).finally(function() {
            mfaSubmitting = false;
            document.getElementById("mfa-submit").disabled = false;
        });
    }

    // Keep the session token the server returned (if any — the gateway's
    // HttpOnly session cookie works without it), then either continue to
    // the dashboard or, for a session limited to a password change,
    // ask for the new password first.
    function storeSession(data) {
        if (data && data.session_token) {
            sessionStorage.setItem("bridge_session_token", data.session_token);
        }
        sessionStorage.removeItem("bridge_api_key");
    }

    function finishLogin(data, currentPassword) {
        storeSession(data);
        if (data && data.password_change_required) {
            showPasswordChange(data.session_token || "", currentPassword);
            return;
        }
        window.location.replace(_nextUrl);
    }

    function showPasswordChange(token, currentPassword) {
        passwordChangeCredentials = { token: token, currentPassword: currentPassword, submitting: false };
        setLoading(false);
        hideMfa();
        submitBtn.style.display = "none";
        var panel = document.getElementById("panel-login");
        var section = document.getElementById("pwchange-section");
        if (!section) {
            section = document.createElement("div");
            section.id = "pwchange-section";
            section.className = "mfa-section";
            section.style.display = "block";
            var note = document.createElement("p");
            note.className = "form-label";
            note.textContent = "You must choose a new password before continuing.";
            var p1 = document.createElement("input");
            p1.type = "password";
            p1.id = "pwchange-new";
            p1.className = "form-input";
            p1.placeholder = "New password (min. 8 characters)";
            p1.autocomplete = "new-password";
            var p2 = document.createElement("input");
            p2.type = "password";
            p2.id = "pwchange-confirm";
            p2.className = "form-input";
            p2.placeholder = "Repeat new password";
            p2.autocomplete = "new-password";
            var btn = document.createElement("button");
            btn.className = "btn-login";
            btn.id = "pwchange-submit";
            btn.textContent = "Change password";
            section.appendChild(note);
            section.appendChild(p1);
            section.appendChild(p2);
            section.appendChild(btn);
            panel.appendChild(section);
            btn.addEventListener("click", submitPasswordChange);
            p2.addEventListener("keydown", passwordChangeKeydown);
        }
        document.getElementById("pwchange-new").focus();
    }

    function passwordChangeKeydown(e) {
        if (e.key === "Enter") submitPasswordChange();
    }

    function requirePasswordLogin() {
        // The password is already committed and every old session is revoked.
        // Do not retain credentials or a listener that can retry the old password.
        passwordChangeCredentials = null;
        ["bridge_session_token", "bridge_api_key", "bridge_admin_key"].forEach(function(key) {
            // Storage can become unavailable after login. The server already
            // revoked these values; still clear every input and listener below.
            try { sessionStorage.removeItem(key); } catch (_) {}
        });
        document.getElementById("password").value = "";
        document.getElementById("apikey").value = "";
        var section = document.getElementById("pwchange-section");
        if (section) {
            document.getElementById("pwchange-new").value = "";
            var confirm = document.getElementById("pwchange-confirm");
            confirm.value = "";
            confirm.removeEventListener("keydown", passwordChangeKeydown);
            document.getElementById("pwchange-submit").removeEventListener("click", submitPasswordChange);
            section.remove();
        }
        activeTab = "login";
        document.querySelectorAll(".login-tab").forEach(function(tab) {
            tab.classList.toggle("active", tab.getAttribute("data-tab") === "login");
        });
        document.getElementById("panel-login").classList.add("active");
        document.getElementById("panel-apikey").classList.remove("active");
        hideMfa();
        setLoading(false);
        showError("Password changed. Sign in with your new password.");
        document.getElementById("password").focus();
    }

    function submitPasswordChange() {
        var credentials = passwordChangeCredentials;
        if (!credentials || credentials.submitting) return;
        var token = credentials.token;
        var currentPassword = credentials.currentPassword;
        var p1 = document.getElementById("pwchange-new").value;
        var p2 = document.getElementById("pwchange-confirm").value;
        if (p1.length < 8) { showError("The new password needs at least 8 characters"); return; }
        if (p1 !== p2) { showError("The passwords do not match"); return; }
        credentials.submitting = true;
        document.getElementById("pwchange-submit").disabled = true;
        hideError();
        var headers = { "Content-Type": "application/json", "Accept": "application/json" };
        if (token) headers["Authorization"] = "Bearer " + token;
        var csrf = (document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/) || [])[1] || "";
        if (csrf) headers["X-CSRF-Token"] = csrf;
        fetch("/api/auth/change-password", {
            method: "POST",
            headers: headers,
            body: JSON.stringify({ current_password: currentPassword, new_password: p1 }),
            credentials: "same-origin"
        }).then(function(r) {
            if (!r.ok) return r.json().catch(function() { return {}; }).then(function(e) { return Promise.reject(e); });
            return r.json();
        }).then(function(data) {
            if (data && data.reauthentication_required === true) {
                requirePasswordLogin();
                return;
            }
            // A replacement session is available, or the gateway lifted the
            // password-change restriction on the current session.
            storeSession(data);
            window.location.replace(_nextUrl);
        }).catch(function(err) {
            showError((err && err.detail) || "Password change failed");
        }).finally(function() {
            // Completion may have removed this form and discarded its secrets.
            if (passwordChangeCredentials === credentials) {
                credentials.submitting = false;
                document.getElementById("pwchange-submit").disabled = false;
            }
        });
    }

    function submitApiKey() {
        var key = document.getElementById("apikey").value.trim();
        if (!key) { showError("Enter an API key"); return; }
        sessionStorage.setItem("bridge_api_key", key);
        sessionStorage.removeItem("bridge_session_token");
        window.location.replace(_nextUrl);
    }

    function handleSubmit() {
        if (activeTab === "login") submitLogin();
        else submitApiKey();
    }

    submitBtn.addEventListener("click", handleSubmit);
    document.getElementById("mfa-submit").addEventListener("click", submitMfa);
    document.getElementById("password").addEventListener("keydown", function(e) { if (e.key === "Enter") handleSubmit(); });
    document.getElementById("username").addEventListener("keydown", function(e) { if (e.key === "Enter") handleSubmit(); });
    document.getElementById("apikey").addEventListener("keydown", function(e) { if (e.key === "Enter") handleSubmit(); });
    document.getElementById("mfa-code").addEventListener("keydown", function(e) { if (e.key === "Enter") submitMfa(); });

    // Caps Lock indicator — toggle while the password field has focus.
    var passwordEl = document.getElementById("password");
    var capsWarnEl = document.getElementById("caps-lock-warning");
    function updateCapsLockIndicator(e) {
        if (!capsWarnEl || !e.getModifierState) return;
        var on = e.getModifierState("CapsLock");
        capsWarnEl.classList.toggle("visible", !!on && document.activeElement === passwordEl);
    }
    passwordEl.addEventListener("keydown", updateCapsLockIndicator);
    passwordEl.addEventListener("keyup", updateCapsLockIndicator);
    passwordEl.addEventListener("blur", function() { capsWarnEl.classList.remove("visible"); });

    document.getElementById("username").focus();
});
