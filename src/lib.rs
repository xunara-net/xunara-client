#![cfg(any(target_os = "linux", target_os = "android"))]

pub mod config;
pub mod control;
pub mod derp;
pub mod diagnostic;
pub mod discovery;
pub mod dns;
pub mod dns_stack;
pub mod engine;
pub mod filter;
pub mod mobile;
pub mod model;
#[cfg(target_os = "linux")]
pub mod network;
#[cfg(target_os = "android")]
#[path = "network_android.rs"]
pub mod network;
pub mod state;
pub mod transport;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
