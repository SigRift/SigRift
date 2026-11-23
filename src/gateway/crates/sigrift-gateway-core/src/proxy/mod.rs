//! Reverse proxy to the Python (SigRift bridge) backend.
//!
//! All routes not handled natively by Rust are forwarded to Python.
//! The proxy injects trust headers so Python knows the request was
//! authenticated by Rust.

pub mod handler;
pub mod ws_proxy;
