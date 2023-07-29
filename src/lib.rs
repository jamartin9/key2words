#[cfg(target_arch = "wasm32")]
pub mod agent;
#[cfg(not(target_arch = "wasm32"))]
pub mod cli;
pub mod keys;
#[cfg(target_arch = "wasm32")]
pub mod web;
