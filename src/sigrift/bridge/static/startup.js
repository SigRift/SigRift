(function() {
  var fill = document.getElementById('progress-fill');
  var badge = document.getElementById('state-badge');
  var dbSize = document.getElementById('db-size');
  var elapsed = document.getElementById('elapsed');
  var estRemaining = document.getElementById('est-remaining');
  var message = document.getElementById('message');
  var redirectMsg = document.getElementById('redirect-msg');

  // Estimate: ~30 seconds per GB for quick_check
  var SECS_PER_GB = 30;

  function updateUI(data) {
    var state = data.state;
    var sizeMb = data.db_size_mb || 0;
    var elapsedS = data.elapsed_s || 0;
    var sizeGb = sizeMb / 1000;
    var estTotal = sizeGb * SECS_PER_GB;

    dbSize.textContent = sizeMb.toFixed(0);
    elapsed.textContent = elapsedS.toFixed(0) + 's';

    // Badge
    badge.className = 'state-badge state-' + state;
    var labels = {
      pending: 'Pending',
      not_started: 'Not started',
      running: 'Running',
      passed: 'Passed',
      failed: 'Failed',
      skipped: 'Skipped',
      error: 'Error',
    };
    badge.textContent = labels[state];

    if (state === 'running') {
      if (estTotal > 0) {
        var pct = Math.min((elapsedS / estTotal) * 100, 95);
        fill.className = 'progress-bar-fill';
        fill.style.width = pct + '%';
        var remaining = Math.max(estTotal - elapsedS, 0);
        estRemaining.textContent = remaining.toFixed(0) + 's';
      } else {
        fill.className = 'progress-bar-fill indeterminate';
        estRemaining.textContent = '--';
      }
      message.innerHTML = '<span class="spinner"></span> Checking database integrity (' + sizeMb.toFixed(0) + ' MB)...';
    } else if (state === 'passed') {
      fill.className = 'progress-bar-fill';
      fill.style.width = '100%';
      fill.style.background = 'linear-gradient(90deg, #22c55e, #4ade80)';
      estRemaining.textContent = '0s';
      message.textContent = 'Integrity check passed. Redirecting...';
      redirectMsg.textContent = 'Redirecting to dashboard in 2 seconds...';
      setTimeout(function() { window.location.href = '/dashboard'; }, 2000);
    } else if (state === 'skipped') {
      fill.className = 'progress-bar-fill';
      fill.style.width = '100%';
      fill.style.background = '#6b7280';
      estRemaining.textContent = '--';
      message.textContent = 'Integrity check skipped (BRIDGE_SKIP_INTEGRITY_CHECK).';
      redirectMsg.textContent = 'Redirecting to dashboard in 1 second...';
      setTimeout(function() { window.location.href = '/dashboard'; }, 1000);
    } else if (state === 'failed' || state === 'error') {
      fill.className = 'progress-bar-fill';
      fill.style.width = '100%';
      fill.style.background = '#ef4444';
      estRemaining.textContent = '--';
      message.textContent = 'Check failed: ' + (data.error || 'unknown error');
      message.style.color = '#fca5a5';
    } else {
      // poll() accepts only the known states; these are pending/not_started.
      fill.className = 'progress-bar-fill indeterminate';
      estRemaining.textContent = '--';
      message.innerHTML = '<span class="spinner"></span> Waiting for database initialization...';
    }
  }

  function poll() {
    fetch('/api/integrity-status')
      .then(function(r) {
        if (!r.ok) throw new Error('Integrity status unavailable');
        return r.json();
      })
      .then(function(data) {
        // Treat unavailable/malformed status as retryable, never as a passed
        // check. In particular, an error response may still contain JSON.
        if (!data || ['pending', 'not_started', 'running', 'passed', 'skipped', 'failed', 'error'].indexOf(data.state) === -1) {
          throw new Error('Integrity status unavailable');
        }
        updateUI(data);
        if (data.state === 'running' || data.state === 'pending' || data.state === 'not_started') {
          setTimeout(poll, 1000);
        }
      })
      .catch(function() {
        message.innerHTML = '<span class="spinner"></span> Connecting to server...';
        setTimeout(poll, 2000);
      });
  }

  poll();
})();
