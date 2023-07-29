/*
 *
 * SPDX-FileCopyrightText: 2022 Justin Martin <jaming@protonmail.com>
 * SPDX-License-Identifier: LGPL-2.0-or-later
 *
 */

#[cfg(not(target_arch = "wasm32"))]
use key2words::cli;

use anyhow::Result;

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc; // use jemalloc for perf

#[tokio::main]
async fn main() -> Result<()> {
    // TODO SSR when yew-agent(webworker) supports
    #[cfg(not(target_arch = "wasm32"))]
    {
        cli::cli()
    }
}
