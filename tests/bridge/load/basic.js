/**
 * k6 load test for The Bridge API.
 *
 * Install: https://k6.io/docs/get-started/installation/
 * Run:     k6 run tests/load/basic.js
 * Custom:  k6 run --vus 50 --duration 30s tests/load/basic.js
 *
 * Environment:
 *   BRIDGE_URL  - Target URL (default: http://localhost:8444)
 *   API_KEY     - API key for authenticated requests
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const BASE_URL = __ENV.BRIDGE_URL || 'http://localhost:8444';
const API_KEY = __ENV.API_KEY || '';

// Custom metrics
const errorRate = new Rate('errors');
const loginDuration = new Trend('login_duration');

export const options = {
    stages: [
        { duration: '10s', target: 10 },  // Ramp up
        { duration: '30s', target: 10 },  // Sustained
        { duration: '5s', target: 0 },    // Ramp down
    ],
    thresholds: {
        http_req_duration: ['p(95)<500'],  // 95th percentile under 500ms
        errors: ['rate<0.1'],              // Error rate under 10%
    },
};

const headers = API_KEY
    ? { 'X-API-Key': API_KEY, 'Content-Type': 'application/json' }
    : { 'Content-Type': 'application/json' };

export default function () {
    // Health check (unauthenticated)
    const health = http.get(`${BASE_URL}/health`);
    check(health, { 'health 200': (r) => r.status === 200 });
    errorRate.add(health.status !== 200);

    // Version (unauthenticated)
    const version = http.get(`${BASE_URL}/api/version`);
    check(version, { 'version 200': (r) => r.status === 200 });
    errorRate.add(version.status !== 200);

    // Authenticated endpoints (if API key provided)
    if (API_KEY) {
        const recent = http.get(`${BASE_URL}/api/detections/recent?minutes=5&limit=10`, { headers });
        check(recent, { 'recent 200': (r) => r.status === 200 });
        errorRate.add(recent.status !== 200);

        const summary = http.get(`${BASE_URL}/api/detections/summary`, { headers });
        check(summary, { 'summary 200': (r) => r.status === 200 });
        errorRate.add(summary.status !== 200);
    }

    // Login attempt (unauthenticated — tests rate limiting)
    const loginStart = Date.now();
    const login = http.post(`${BASE_URL}/api/auth/login`, JSON.stringify({
        username: `loadtest_user_${__VU}`,
        password: 'wrong_password',
    }), { headers: { 'Content-Type': 'application/json' } });
    loginDuration.add(Date.now() - loginStart);
    check(login, { 'login rejected': (r) => r.status === 401 || r.status === 429 });

    sleep(1);
}

export function handleSummary(data) {
    return {
        stdout: JSON.stringify({
            total_requests: data.metrics.http_reqs.values.count,
            avg_duration_ms: Math.round(data.metrics.http_req_duration.values.avg),
            p95_duration_ms: Math.round(data.metrics.http_req_duration.values['p(95)']),
            error_rate: data.metrics.errors ? data.metrics.errors.values.rate : 0,
        }, null, 2) + '\n',
    };
}
