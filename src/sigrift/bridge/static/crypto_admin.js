/**
 * Crypto Key Management — Admin Panel module.
 *
 * Manages crypto keys for protocol decryption: list, import, revoke,
 * and manual decrypt operations.
 */
(function() {
    'use strict';

    var keysTbody = document.getElementById('crypto-keys-tbody');
    if (!keysTbody) return;

    var API = '/api/crypto';

    function getAdminKey() {
        return sessionStorage.getItem('bridge_admin_key') ||
               sessionStorage.getItem('bridge_api_key') || '';
    }

    function apiFetch(path, opts) {
        opts = opts || {};
        var h = opts.headers || {};
        h['Accept'] = 'application/json';
        if (opts.body && typeof opts.body === 'object' && !(opts.body instanceof FormData)) {
            h['Content-Type'] = 'application/json';
            opts.body = JSON.stringify(opts.body);
        }
        var key = getAdminKey();
        if (key) h['X-API-Key'] = key;
        var sessionToken = sessionStorage.getItem('bridge_session_token');
        if (sessionToken && !key) h['X-Session-Token'] = sessionToken;
        opts.headers = h;
        opts.credentials = 'same-origin';
        return fetch(path, opts).then(function(r) {
            if (!r.ok) {
                // Error('HTTP <status>') keeping the status and the server's
                // string `detail` from a JSON body (callers show it as text).
                var error = new Error('HTTP ' + r.status);
                error.status = r.status;
                return r.json().then(function(body) {
                    if (body && typeof body.detail === 'string') error.detail = body.detail;
                    return Promise.reject(error);
                }, function() { return Promise.reject(error); });
            }
            if (r.status === 204) return null;
            return (r.headers.get('content-type') || '').indexOf('json') !== -1 ? r.json() : r;
        });
    }

    // ── Key List ───────────────────────────────────────────────────

    function loadKeys() {
        apiFetch(API + '/keys').then(function(data) {
            var keys = Array.isArray(data) ? data : (data.keys || []);
            keysTbody.innerHTML = '';
            var empty = document.getElementById('crypto-keys-empty');

            if (keys.length === 0) {
                if (empty) empty.style.display = '';
                return;
            }
            if (empty) empty.style.display = 'none';

            keys.forEach(function(k) {
                var tr = document.createElement('tr');
                var revokeBtn = '<button class="btn btn-sm" style="color:var(--accent-red,#ef4444);" data-revoke="' + esc(k.key_id) + '">Revoke</button>';
                tr.innerHTML =
                    '<td>' + esc(k.protocol) + '</td>' +
                    '<td>' + esc(k.label) + '</td>' +
                    '<td>' + esc(k.algorithm) + '</td>' +
                    '<td>' + esc(k.source || 'manual') + '</td>' +
                    '<td>' + esc(k.key_len || '') + ' bytes</td>' +
                    '<td>' + fmtTime(k.created_at) + '</td>' +
                    '<td>' + revokeBtn + '</td>';
                keysTbody.appendChild(tr);
            });

            // Wire revoke buttons
            keysTbody.querySelectorAll('[data-revoke]').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    revokeKey(btn.getAttribute('data-revoke'));
                });
            });
        }).catch(function(e) {
            // A failed listing is not an empty store: hide "No crypto keys".
            var empty = document.getElementById('crypto-keys-empty');
            if (empty) empty.style.display = 'none';
            keysTbody.innerHTML = '<tr><td colspan="7" style="color:var(--accent-red);">Error: ' + esc((e && (e.detail || e.message)) || 'Unknown') + '</td></tr>';
        });
    }

    // ── Revoke Key ─────────────────────────────────────────────────

    function revokeKey(keyId) {
        if (!confirm('Revoke crypto key ' + keyId + '? This cannot be undone.')) return;

        apiFetch(API + '/keys/' + encodeURIComponent(keyId), {
            method: 'DELETE'
        }).then(function() {
            loadKeys();
        }).catch(function(e) {
            alert('Error revoking key: ' + (e.detail || e.message || 'Unknown'));
        });
    }

    // ── Import Key ─────────────────────────────────────────────────

    function importKey() {
        var protocol = document.getElementById('crypto-import-protocol');
        var name = document.getElementById('crypto-import-name');
        var hex = document.getElementById('crypto-import-hex');
        var algorithm = document.getElementById('crypto-import-algorithm');
        var result = document.getElementById('crypto-import-result');

        if (!name || !name.value.trim()) { alert('Key name is required'); return; }
        if (!hex || !hex.value.trim()) { alert('Key hex is required'); return; }

        // Validate hex
        var hexVal = hex.value.trim().replace(/\s+/g, '');
        if (!/^[0-9a-fA-F]+$/.test(hexVal)) { alert('Invalid hex value'); return; }

        apiFetch(API + '/keys', {
            method: 'POST',
            body: {
                protocol: protocol ? protocol.value : 'generic',
                key_name: name.value.trim(),
                raw_key_hex: hexVal,
                algorithm: algorithm ? algorithm.value : 'aes-128'
            }
        }).then(function(data) {
            if (result) {
                result.style.display = '';
                result.style.color = 'var(--accent-green)';
                result.textContent = 'Key imported: ' + (data.key_id || 'OK');
            }
            // Clear form
            if (name) name.value = '';
            if (hex) hex.value = '';
            loadKeys();
            setTimeout(function() { if (result) result.style.display = 'none'; }, 5000);
        }).catch(function(e) {
            if (result) {
                result.style.display = '';
                result.style.color = 'var(--accent-red)';
                result.textContent = 'Error: ' + (e.detail || e.message || 'Unknown');
            }
        });
    }

    // ── Manual Decrypt ─────────────────────────────────────────────

    function manualDecrypt() {
        var protocol = document.getElementById('crypto-decrypt-protocol');
        var payload = document.getElementById('crypto-decrypt-payload');
        var keyId = document.getElementById('crypto-decrypt-key-id');
        var resultDiv = document.getElementById('crypto-decrypt-result');
        var output = document.getElementById('crypto-decrypt-output');

        if (!payload || !payload.value.trim()) { alert('Payload hex is required'); return; }

        var hexVal = payload.value.trim().replace(/\s+/g, '');
        if (!/^[0-9a-fA-F]+$/.test(hexVal)) { alert('Invalid hex value'); return; }

        var body = {
            protocol: protocol ? protocol.value : '',
            payload_hex: hexVal
        };
        if (keyId && keyId.value.trim()) {
            body.key_id = keyId.value.trim();
        }

        apiFetch(API + '/decrypt', {
            method: 'POST',
            body: body
        }).then(function(data) {
            if (resultDiv) resultDiv.style.display = '';
            if (output) {
                var text = '';
                if (data.success === false) text += 'Failed: ' + (data.error || 'unknown') + '\n';
                if (data.plaintext_hex) text += 'Plaintext (hex): ' + data.plaintext_hex + '\n';
                if (data.key_id) text += 'Key used: ' + data.key_id + '\n';
                if (data.algorithm) text += 'Algorithm: ' + data.algorithm + '\n';
                if (data.confidence != null) text += 'Confidence: ' + (data.confidence * 100).toFixed(1) + '%\n';
                if (!text) text = JSON.stringify(data, null, 2);
                output.textContent = text;
            }
        }).catch(function(e) {
            if (resultDiv) resultDiv.style.display = '';
            if (output) {
                output.textContent = 'Error: ' + (e.detail || e.message || 'Decryption failed');
            }
        });
    }

    // ── Wire UI ────────────────────────────────────────────────────

    var importBtn = document.getElementById('crypto-import-btn');
    if (importBtn) importBtn.addEventListener('click', importKey);

    var decryptBtn = document.getElementById('crypto-decrypt-btn');
    if (decryptBtn) decryptBtn.addEventListener('click', manualDecrypt);

    // Load when tab becomes visible
    var observer = new MutationObserver(function() {
        var tab = document.getElementById('tab-crypto');
        if (tab && tab.style.display !== 'none') loadKeys();
    });
    var tabCrypto = document.getElementById('tab-crypto');
    if (tabCrypto) {
        observer.observe(tabCrypto, { attributes: true, attributeFilter: ['style'] });
    }
})();
