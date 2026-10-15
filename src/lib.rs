#![cfg(target_os = "linux")]

pub mod config;
pub mod control;
pub mod derp;
pub mod discovery;
pub mod engine;
pub mod filter;
pub mod model;
pub mod network;
pub mod state;
pub mod transport;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
