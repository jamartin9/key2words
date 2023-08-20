/*
 *
 * SPDX-FileCopyrightText: 2022 Justin Martin <jaming@protonmail.com>
 * SPDX-License-Identifier: LGPL-2.0-or-later
 *
 */

use anyhow::Result;
use key2words_cli::cli;

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc; // use jemalloc for perf

#[tokio::main]
async fn main() -> Result<()> {
    // TODO SSR when yew-agent(webworker) supports
    cli()
}
