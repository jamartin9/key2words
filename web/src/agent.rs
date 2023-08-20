use anyhow::{anyhow, Result};
use bip39::Language;
use gloo::console;
use key2words_core::{Converter, KeyConverter};
use serde::{Deserialize, Serialize};
use yew_agent::{HandlerId, Public, Worker, WorkerLink};

pub struct MyWorker {
    link: WorkerLink<Self>,
}

#[derive(Serialize, Deserialize)]
pub struct WorkerInput {
    pub contents: String,
    pub pass: String,
    pub infmt: String,
    pub outfmt: String,
}

#[derive(Serialize, Deserialize)]
pub struct WorkerOutput {
    pub converted: String,
    pub fmt: String,
    pub bin: Option<Vec<u8>>,
}

impl Worker for MyWorker {
    type Input = WorkerInput;
    type Message = ();
    type Output = WorkerOutput;
    type Reach = Public<Self>;

    fn create(link: WorkerLink<Self>) -> Self {
        Self { link }
    }

    fn update(&mut self, _msg: Self::Message) {
        // no messaging
    }

    fn handle_input(&mut self, msg: Self::Input, id: HandlerId) {
        // this runs in a web worker
        // and does not block the main
        // browser thread!

        let input = msg.contents;
        let pass = msg.pass;
        let infmt = msg.infmt;
        let outfmt = msg.outfmt;

        let key: Option<String> = if pass.is_empty() {
            console::log!("Empty Password");
            None
        } else {
            console::log!("Using Password");
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
                console::log!("running converter");
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
        let output = Self::Output {
            converted: match result {
                Ok(content) => content, // set converted to rerender form state
                Err(err) => {
                    console::log!(err.to_string());
                    err.to_string()
                }
            },
            fmt: outfmt,
            bin: binary,
        };
        self.link.respond(id, output);
    }

    fn name_of_resource() -> &'static str {
        "worker.js"
    }

    fn resource_path_is_relative() -> bool {
        true
    }
}
