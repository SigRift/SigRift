//! WebSocket feeds for real-time detection and anomaly streaming.

pub mod anomaly_feed;
pub mod auth;
pub mod feed;
#[cfg(test)]
pub(crate) mod test_harness;
