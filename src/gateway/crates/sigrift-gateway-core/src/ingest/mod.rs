//! Ingest pipeline — batch receive, validate, normalize, score, correlate, store, broadcast.

pub mod binding;
pub mod handler;
pub mod hooks;
pub mod normalize;
pub mod validate;
