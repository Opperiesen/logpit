//! LogPit: a small, self-contained log aggregator.

pub mod alerts;
pub mod api;
pub mod auth;
pub mod cef;
pub mod config;
pub mod export;
pub mod framing;
pub mod health;
pub mod ingest;
pub mod metrics;
pub mod model;
pub mod query;
pub mod rules;
pub mod silence;
pub mod stats;
pub mod store;
pub mod structured;
pub mod syslog;
pub mod tls;
pub mod webhook;
