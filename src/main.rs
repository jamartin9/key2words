/*
 *
 * SPDX-FileCopyrightText: 2022 Justin Martin <jaming@protonmail.com>
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 */

use bip39::{Language, Mnemonic};
use clap::{ArgGroup, Parser};
use ssh_key::private::{Ed25519Keypair, KeypairData};
use ssh_key::{rand_core::OsRng, LineEnding, PrivateKey};
use zeroize::Zeroizing;

// converts 24 words with a comment into (un)encrypted ed25519 ssh key
fn restore_openssh_key(
    words: &str,
    comment: &str,
    enc_key: Option<&str>,
    lang: Language,
) -> (Zeroizing<String>, Zeroizing<String>) {
    let mnem = Mnemonic::from_phrase(words, lang).expect("Could not create mnemonic");
    // ignore the checksum byte
    let ent_slice: [u8; 32] = mnem.entropy()[..32]
        .try_into()
        .expect("Could not get entropy");
    let ed_kp = Ed25519Keypair::from_seed(&ent_slice);
    let mut restored_ssh_key =
        PrivateKey::new(KeypairData::from(ed_kp), comment).expect("Could not create ssh key");
    let public_ssh_key = restored_ssh_key
        .public_key()
        .to_openssh()
        .expect("Could not encode public key");
    if let Some(enc) = enc_key {
        restored_ssh_key = restored_ssh_key
            .encrypt(&mut OsRng, enc)
            .expect("Failed to encrypt private ssh key");
    }

    #[cfg(target_os = "windows")]
    let line_ending = LineEnding::CRLF;
    #[cfg(not(target_os = "windows"))]
    let line_ending = LineEnding::LF;

    (
        restored_ssh_key
            .to_openssh(line_ending)
            .expect("Could not encode openssh key"),
        Zeroizing::new(public_ssh_key),
    )
}

// creates mnemonic with unencrypted private key
fn create_restore_words(
    key: &str,
    enc_key: Option<&str>,
    lang: Language,
) -> (Zeroizing<String>, Zeroizing<String>) {
    let mut private_key = PrivateKey::from_openssh(key).expect("Failed to parse private key");
    if let Some(enc) = enc_key {
        // ignore non encrypted key
        if private_key.is_encrypted() {
            private_key = private_key.decrypt(enc).expect("Could not decrypt key");
        }
    }
    let comment = private_key.comment().to_owned();
    let key_pair = private_key
        .key_data()
        .ed25519()
        .expect("Failed to get ed25519 key");
    let priv_key = key_pair.private.to_owned();
    let mnem =
        Mnemonic::from_entropy(&priv_key.to_bytes(), lang).expect("Failed to create mnemonic");
    (
        Zeroizing::new(mnem.phrase().to_string()),
        Zeroizing::new(comment),
    )
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
            ArgGroup::new("pub")
                .requires("mainopts")
                .conflicts_with_all(&["key", "enckey"])
                .args(&["pubkey"]),
        ))]
struct Args {
    /// Path to the ed25519 private key
    #[clap(short, long)]
    key: Option<String>,

    /// List of space separated words ending with the comment
    #[clap(short, long)]
    words: Option<String>,

    /// Public key only
    #[clap(short, long)]
    pubkey: bool,

    /// Encryption passphrase for private key
    #[clap(short, long)]
    enckey: Option<String>,

    /// Language for words ( en , es , ko , ja , it , fr , zh-hant , zh-hans )
    #[clap(short, long)]
    lang: Option<String>,
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
        // 24 words + 1 comment appended to the end
        if wordlist.split(' ').count() == 25 {
            let word_vec: Vec<&str> = wordlist.rsplitn(2, ' ').collect();
            let (restored_key, public_key) = restore_openssh_key(
                word_vec[1],
                word_vec[0],
                args.enckey.as_deref(),
                word_list_lang,
            );
            if args.pubkey {
                println!("{}", public_key.as_str());
            } else {
                println!("{}", restored_key.as_str());
            }
        }
    } else if let Some(keypath) = args.key {
        let ssh_key = Zeroizing::new(
            std::fs::read_to_string(std::path::Path::new(&keypath)).expect("Invalid Path"),
        );
        let (mut words, comment) =
            create_restore_words(ssh_key.as_str(), args.enckey.as_deref(), word_list_lang);
        words.push(' ');
        words.push_str(&comment);
        println!("{}", words.as_str());
    }
}

#[test]
fn test_convert_keys() {
    let ssh_key = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBI71SQOe
5IyJgg8OmORqY+AAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN
796jTiQfZfG1KaT0PtFDJ/XFSqtiAAAAoLI20UvV1GETLH7xUwRj497NEd8u+acgMF2yt7
KYNTJzcrim3GDCCBUPCmCMpSAwHxRz9V+yLCe9YzjX0MxbopyjuaJn3e4AX2GL7jZnE6OS
zmnJjP7CbvVr8ZJpg5T1c/uuahXfWrlb15MUK5OsdocSG2lEXHUXCiPZIfmMX7XmzlpzQa
NKQ53QA1ysdt7QVeG619TSeOHlqAKw34WhCWk=
-----END OPENSSH PRIVATE KEY-----
"#;
    let ssh_pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti user@example.com";
    let ssh_comment = "user@example.com";
    let ssh_words = "render current master pear scrap hope mad mix pill penalty fresh mixture unaware armor lift million hard alley oppose pulse angry suspect element price";
    let lang = Language::English;
    let (mywords, comment) = create_restore_words(ssh_key, Some("doggy"), lang);
    let (_restored_key, public_key) = restore_openssh_key(&mywords, &comment, Some("doggy"), lang);
    assert_eq!(ssh_pub, public_key.as_str(), "Public keys are not equal");
    assert_eq!(ssh_comment, comment.as_str(), "Comments are not equal");
    assert_eq!(ssh_words, mywords.as_str(), "Words are not equal");
}
