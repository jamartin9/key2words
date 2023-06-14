/*
 *
 * SPDX-FileCopyrightText: 2022 Justin Martin <jaming@protonmail.com>
 * SPDX-License-Identifier: LGPL-2.0-or-later
 *
 */
#[cfg(not(target_arch = "wasm32"))]
pub mod cli;
#[cfg(target_arch = "wasm32")]
pub mod web;

pub mod keys;
use anyhow::Result;

fn main() -> Result<()> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        cli::cli()
    }
    #[cfg(target_arch = "wasm32")]
    {
        web::web();
        Ok(())
    }
}
