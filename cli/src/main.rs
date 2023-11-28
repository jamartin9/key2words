#[cfg(feature = "eyra")]
extern crate eyra;

#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc; // use jemalloc for perf

use anyhow::Result;
use key2words_cli::cli;

#[tokio::main]
async fn main() -> Result<()> {
    cli().await
}
