# Load Tests (k6)

API load and stress testing for the SigRift bridge.

## Setup

Install k6: https://k6.io/docs/get-started/installation/

```bash
# Ubuntu/Debian
sudo gpg -k
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D68
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update && sudo apt-get install k6
```

## Running

```bash
# Basic (10 VUs, 45s)
k6 run tests/bridge/load/basic.js

# Custom
k6 run --vus 50 --duration 60s tests/bridge/load/basic.js

# With auth
BRIDGE_URL=http://localhost:8444 API_KEY=your-key k6 run tests/bridge/load/basic.js
```

## Thresholds

- 95th percentile response time: < 500ms
- Error rate: < 10%
