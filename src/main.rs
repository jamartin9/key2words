/*
 *
 * SPDX-FileCopyrightText: 2022 Justin Martin <jaming@protonmail.com>
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

pub mod keys;
use bip39::Language;
use clap::{ArgGroup, Parser};
use keys::{Converter, KeyConverter};
use std::path::PathBuf;

/* Helpers */
fn write_vec_to_file(contents: Vec<u8>, file: &str) {
    let mut exported = std::fs::File::create(file).expect("Could not create file");
    use std::io::Write;
    exported.write_all(&contents).expect("Could not write file");
}

fn write_string_to_file(contents: String, file: &str) {
    let mut exported = std::fs::File::create(file).expect("Could not create file");
    use std::io::Write;
    exported
        .write_all(contents.as_bytes())
        .expect("Could not write file");
}

/// Converts ed25519 keys using bip39
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[clap(group(
            ArgGroup::new("mainopts")
                .required(true)
                .args(&["key", "words"]),
        ))]
#[clap(group(
            ArgGroup::new("either")
                .requires("mainopts")
                .conflicts_with_all(&["words", "ssh", "gpg", "comment", "ctime", "duration"])
                .args(&["key"]),
        ))]
struct Args {
    /// Path to the ed25519 private key of either ssh or gpg
    #[clap(short, long)]
    key: Option<PathBuf>,

    /// List of 24 space separated words
    #[clap(short, long)]
    words: Option<String>,

    /// comment for gpg/ssh key export
    #[clap(short, long)]
    comment: Option<String>,

    /// Generate ssh key
    #[clap(short, long)]
    ssh: bool,

    /// Generate tor key
    #[clap(short, long)]
    tor: bool,

    /// Generate pgp key
    #[clap(short, long)]
    gpg: bool,

    /// Encryption passphrase for private key
    #[clap(short, long)]
    pass: Option<String>,

    /// Language for words ( en , es , ko , ja , it , fr , zh-hant , zh-hans )
    #[clap(short, long)]
    lang: Option<String>,

    /// Duration of key
    #[clap(short, long)]
    duration: Option<u64>,

    /// Creation time of key
    #[clap(short, long)]
    epoch: Option<u64>,
}

fn main() {
    let args = Args::parse();
    // default to English
    let word_list_lang = {
        if let Some(parsed_lang) = args.lang {
            match Language::from_language_code(parsed_lang.as_str()) {
                Some(lang_code) => lang_code,
                None => Language::English,
            }
        } else {
            Language::English
        }
    };
    if let Some(wordlist) = args.words.as_deref() {
        let key_converter = KeyConverter::from_mnemonic(
            wordlist.to_string(),
            word_list_lang,
            args.comment,
            args.pass,
            args.epoch,
            args.duration,
        );
        if args.gpg {
            write_string_to_file(key_converter.to_pgp(), "key.gpg");
        }
        if args.tor {
            write_string_to_file(key_converter.to_tor_address(), "hostname");
            write_vec_to_file(key_converter.to_tor_service(), "hs_ed25519_secret_key");
            write_vec_to_file(key_converter.to_tor_pub(), "hs_ed25519_public_key");
        }
        if args.ssh {
            let (ssh_key, pub_key) = key_converter.to_ssh();
            write_string_to_file(pub_key.to_string(), "ed_ed25519.pub");
            write_string_to_file(ssh_key.to_string(), "id_ed25519");
        }
    } else if let Some(keypath) = args.key {
        // check for .gpg and load as ssh otherwise
        let key_contents = std::fs::read_to_string(&keypath).expect("Invalid Path");
        let key_converter = {
            if "gpg" == keypath.extension().expect("Could not get extension") {
                KeyConverter::from_gpg(key_contents, args.pass, word_list_lang)
            } else {
                KeyConverter::from_ssh(key_contents, args.pass, word_list_lang)
            }
        };

        let words = key_converter.to_words();
        // print words/comment/ctime/duration
        println!("{}", words.as_str());
        println!("{}", key_converter.comment);
        println!("{:#?}", key_converter.duration);
        println!("{:#?}", key_converter.creation_time);
    }
}
