use anyhow::{anyhow, Result};
use bip39::Language;
use key2words_core::{Converter, KeyConverter};
use serde::{Deserialize, Serialize};
use yew_agent::prelude::*;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct WorkerInput {
    pub contents: String,
    pub pass: String,
    pub infmt: String,
    pub outfmt: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct WorkerOutput {
    pub converted: String,
    pub fmt: String,
    pub bin: Option<Vec<u8>>,
}

// this runs in a web worker and does not block the main browser thread
#[oneshot]
pub async fn ConvertTask(msg: WorkerInput) -> WorkerOutput {
    let input = msg.contents;
    let pass = msg.pass;
    let infmt = msg.infmt;
    let outfmt = msg.outfmt;

    let key: Option<String> = if pass.is_empty() {
        //tracing::info!("Empty Password");
        None
    } else {
        //tracing::info!("Using Password");
        Some(pass)
    };
    let word_list_lang = Language::English;
    let key_convert: Result<KeyConverter> = match infmt.as_str() {
        "SSH" => KeyConverter::from_ssh(input, key, word_list_lang),
        "PGP" => KeyConverter::from_gpg(input, key, word_list_lang),
        "MNEMONIC" => KeyConverter::from_mnemonic(input, word_list_lang, None, key, None, None),
        _ => Err(anyhow!("could not create converter")),
    };
    let mut binary: Option<Vec<u8>> = None;
    let result: Result<String> = match key_convert {
        Err(err) => Err(err),
        Ok(converter) => {
            //tracing::info!("running converter");
            match outfmt.as_str() {
                "PGP" => converter.to_pgp(),
                "SSH" => match converter.to_ssh() {
                    Ok(ssh) => Ok(ssh.0.to_string()),
                    Err(err) => Err(err),
                },
                "TOR" => {
                    binary = converter.to_tor_service().ok();
                    converter.to_tor_address()
                }
                "MNEMONIC" => match converter.to_words() {
                    Ok(words) => Ok(words.to_string()),
                    Err(err) => Err(err),
                },
                _ => Err(anyhow!("Failed to get output format")),
            }
        }
    };
    WorkerOutput {
        converted: match result {
            Ok(content) => content, // set converted to rerender form state
            Err(err) => {
                //tracing::info!("{}", err.to_string());
                err.to_string()
            }
        },
        fmt: outfmt,
        bin: binary,
    }
}
