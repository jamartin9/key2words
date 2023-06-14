/*
 *
 * SPDX-FileCopyrightText: 2022 Justin Martin <jaming@protonmail.com>
 * SPDX-License-Identifier: LGPL-2.0-or-later
 *
 */

//pub mod cli;
pub mod web;
pub mod keys;
use anyhow::Result;


fn main() -> Result<()> {
    web::web();
    Ok(())
    //cli::cli()
}
