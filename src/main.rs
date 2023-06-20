/*
 *
 * SPDX-FileCopyrightText: 2022 Justin Martin <jaming@protonmail.com>
 * SPDX-License-Identifier: LGPL-2.0-or-later
 *
 */

#[cfg(not(target_arch = "wasm32"))]
pub mod cli;

pub mod keys;
use anyhow::Result;

fn main() -> Result<()> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        cli::cli()
    }
}
