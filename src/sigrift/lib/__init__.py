"""SigRift — RF signal classification platform (clean rewrite).

Addresses all 60+ issues identified in the gen2 code review:
- CRITICAL: OFDM pilot/DC overwrite, unbounded phase noise, Butterworth cutoff
- CRITICAL: HackRF int8/uint8 mismatch, zero auth on network endpoints
- HIGH: No early stopping, val/train SNR mismatch, code duplication
- HIGH: Single-family gating risk, MQTT reconnection, socket leaks
- Consolidated signal generation (was duplicated across 8+ files)
- Proper package structure (no nested duplicate package dirs)
- YAML config loading (config.yaml was never loaded in gen2)
"""

__version__ = "4.0.0"
