/*
 *
 * SPDX-FileCopyrightText: 2022 Justin Martin <jaming@protonmail.com>
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

use bip39::{Language, Mnemonic};
use clap::{ArgGroup, Parser};
use ssh_key::private::{Ed25519Keypair, KeypairData};
use ssh_key::{rand_core::OsRng, LineEnding, PrivateKey};
use zeroize::Zeroizing;

fn convert_tor_private(mnem: Mnemonic) -> Vec<u8> {
    use sha2::{Digest, Sha512};
    // ignore the checksum byte
    let ent_slice: [u8; 32] = mnem.entropy()[..32]
        .try_into()
        .expect("Could not get entropy");
    let mut hasher = Sha512::new();
    hasher.update(ent_slice);
    let mut result = hasher.finalize();
    // clamp key for ed25519 spec
    // https://gitlab.torproject.org/dgoulet/torspec/blob/master/rend-spec-v3.txt#L2293
    result[0] &= 248;
    result[31] &= 63; // 127
    result[31] |= 64;
    // hs_ed25519_secret_key
    // "== ed25519v1-secret: type0 ==\x00\x00\x00" appended with the key
    let header = b"== ed25519v1-secret: type0 ==\x00\x00\x00";
    let ret = header
        .iter()
        .chain(result.iter())
        .cloned()
        .collect::<Vec<u8>>();
    ret
}

fn convert_ed25519_pub_to_onion_key(pubkey: &[u8; 32]) -> Vec<u8> {
    // hs_ed25519_public_key
    // tor pubkey file format is "== ed25519v1-public: type0 ==\x00\x00\x00" with the pubkey bytes appended
    let header = b"== ed25519v1-public: type0 ==\x00\x00\x00";
    let res = header
        .iter()
        .chain(pubkey.iter())
        .cloned()
        .collect::<Vec<u8>>();
    res
}

fn convert_ed25519_pub_to_onion_address(pubkey: &[u8; 32]) -> String {
    // concat checksum || pubkey || ver_byte into byte array
    // sha3.Sum256 sum the byte array
    // concat the publickey with the sha bytes then ver_byte
    // base32 encode result for onion address
    use base32ct::{Base32, Encoding};
    use sha3::{Digest, Sha3_256};

    let ver_byte: u8 = 0x03;
    let checksum_str = b".onion checksum";

    let mut hash_me: Vec<u8> = pubkey
        .iter()
        .chain(checksum_str.iter())
        .cloned()
        .collect::<Vec<u8>>();
    hash_me.push(ver_byte);

    let mut hasher = Sha3_256::new();
    hasher.update(hash_me.as_slice());

    let res = hasher.finalize();
    let checksum_bytes: Vec<u8> = res.iter().take(2).cloned().collect::<Vec<u8>>();
    let mut encode_me: Vec<u8> = pubkey
        .iter()
        .chain(checksum_bytes.iter())
        .cloned()
        .collect::<Vec<u8>>();
    encode_me.push(ver_byte);
    // hostname file with .onion appended
    Base32::encode_string(encode_me.as_slice())
}

fn write_tor_keys(words: &str, lang: Language) {
    use std::fs::File;
    use std::io::prelude::*;
    let mnem = Mnemonic::from_phrase(words, lang).expect("Could not create mnemonic");
    let ent_slice: [u8; 32] = mnem.entropy()[..32]
        .try_into()
        .expect("Could not get entropy");
    let ed_kp = Ed25519Keypair::from_seed(&ent_slice);
    // hs_ed25519_public_key
    let pub_key: Vec<u8> = convert_ed25519_pub_to_onion_key(&ed_kp.public.0);
    let mut public_buffer = File::create("hs_ed25519_public_key").expect("Could not create file");
    public_buffer
        .write_all(pub_key.as_slice())
        .expect("could not write bytes");

    // hostname
    let mut onion_addr = convert_ed25519_pub_to_onion_address(&ed_kp.public.0);
    onion_addr.push_str(".onion");
    //println!("hostname is {:#?}", onion_addr);
    let mut host_buffer = File::create("hostname").expect("Could not create file");
    host_buffer
        .write_all(onion_addr.as_bytes())
        .expect("could not write bytes");
    // newline byte
    #[cfg(target_os = "windows")]
    let line_ending = LineEnding::CRLF;
    #[cfg(not(target_os = "windows"))]
    let line_ending = LineEnding::LF;
    host_buffer
        .write_all(line_ending.as_bytes())
        .expect("could not write bytes");

    // hs_ed25519_secret_key
    let priv_key: Vec<u8> = convert_tor_private(mnem);
    let mut secret_buffer = File::create("hs_ed25519_secret_key").expect("Could not create file");
    secret_buffer
        .write_all(priv_key.as_slice())
        .expect("could not write bytes");
    //println!("Only the secret key is needed for onion services.\n The hostname and public key are created by tor on startup of the service.");
}

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

    /// Public key with no private key
    #[clap(short, long)]
    pubkey: bool,

    /// Generate tor service secret key file
    #[clap(short, long)]
    tor: bool,

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
            if args.tor {
                write_tor_keys(word_vec[1], word_list_lang);
            }
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
        if args.tor {
            write_tor_keys(&words, word_list_lang);
        }
        words.push(' ');
        words.push_str(&comment);
        println!("{}", words.as_str());
    }
}

#[test]
fn test_convert_ssh() {
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
    let (restored_key, public_key) = restore_openssh_key(&mywords, &comment, Some("doggy"), lang);
    assert_eq!(ssh_pub, public_key.as_str(), "Public keys are not equal");
    assert_eq!(ssh_comment, comment.as_str(), "Comments are not equal");
    assert_eq!(ssh_words, mywords.as_str(), "Words are not equal");
    assert_ne!(ssh_key, restored_key.as_str(), "Encoded keys are equal"); // only in cases of collisions as encryption and pkdf should ensure uniqueness
}

#[test]
fn test_convert_tor() {
    let onion = "wm7k5436ulpxzkqbbxx55i2oeqpwl4nvfgspipwrimt7lrkkvnrkenid";
    let words = "render current master pear scrap hope mad mix pill penalty fresh mixture unaware armor lift million hard alley oppose pulse angry suspect element price";
    let lang = Language::English;
    let mnem = Mnemonic::from_phrase(words, lang).expect("Could not create mnemonic");
    let ent_slice: [u8; 32] = mnem.entropy()[..32]
        .try_into()
        .expect("Could not get entropy");
    let ed_kp = Ed25519Keypair::from_seed(&ent_slice);
    let onion_addr = convert_ed25519_pub_to_onion_address(&ed_kp.public.0);
    assert_eq!(onion, onion_addr.as_str()); // .onion test

    use base64ct::{Base64, Encoding};
    let key = "PT0gZWQyNTUxOXYxLXNlY3JldDogdHlwZTAgPT0AAABo03+nGlb4tqVIsJnIbIoTBgbLnGHawsrS/y8fHbEXU0eTNWbCyfnM/DBnHbGg1+F72hm2XmxbTs7LmEjBE0tO";
    let priv_key: Vec<u8> = convert_tor_private(mnem);
    let encoded_key = Base64::encode_string(priv_key.as_slice());
    assert_eq!(key, encoded_key.as_str()); // private key test

    let pub_key =
        "PT0gZWQyNTUxOXYxLXB1YmxpYzogdHlwZTAgPT0AAACzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYg==";
    let test_key: Vec<u8> = convert_ed25519_pub_to_onion_key(&ed_kp.public.0);
    let encoded_pub = Base64::encode_string(test_key.as_slice());
    assert_eq!(pub_key, encoded_pub.as_str()); // public key test
}

#[test]
fn test_convert_pgp() {
    let lang = Language::English;
    /*let words = "render current master pear scrap hope mad mix pill penalty fresh mixture unaware armor lift million hard alley oppose pulse angry suspect element price";
    let mnem = Mnemonic::from_phrase(words, lang).expect("Could not create mnemonic");
    let ent_slice: [u8; 32] = mnem.entropy()[..32]
        .try_into()
        .expect("Could not get entropy");
    let ed_kp = Ed25519Keypair::from_seed(&ent_slice);
    let ed_priv_key = ed_kp.private;
    // import key for ed25519
    use sequoia_openpgp::packet::key::{Key4, SecretParts, PrimaryRole};
    use sequoia_openpgp::packet::prelude::*;
    let pgp_key: Key<SecretParts, PrimaryRole> = Key::from(Key4::import_secret_ed25519(&ed_priv_key.to_bytes(), None).expect("Failed to import key"));
    */

    // read ascii armor gpg cert export
    use std::fs::File;
    let mut file = File::open("somefile.asc").expect("No file found");
    use sequoia_openpgp::armor::{Reader, ReaderMode, Kind};
    let r = Reader::from_reader(&mut file, ReaderMode::Tolerant(Some(Kind::SecretKey)));

    // turn the reader into series of certs
    use sequoia_openpgp::parse::Parse;
    use sequoia_openpgp::cert::prelude::*;
    use sequoia_openpgp::serialize::SerializeInto;
    let cert_chain = CertParser::from_reader(r).expect("could not parse");
    for certs in cert_chain {
        match certs {
            Ok(cert) => {
                // get primary secret key
                let sk_key = cert.primary_key().key().clone().parts_into_secret().expect("Could not get secret key");
                // decrypt the secret key
                let secret = sk_key.decrypt_secret(&"Some such password".into()).expect("Could not decrypt secret");
                let keypair = secret.into_keypair().expect("Failed to create keypair");
                let kp_sk = keypair.secret();
                // turn 32 secret key bytes into mnemonic
                use sequoia_openpgp::crypto::mpi::SecretKeyMaterial;
                kp_sk.map(|byte|
                          match byte {
                              SecretKeyMaterial::EdDSA{scalar} => {
                                  println!("ed is {:#?}", scalar.value());
                                  let mnem = Mnemonic::from_entropy(&scalar.value(), lang).expect("Failed to create mnemonic");
                                  println!("Words are : {:#?}", mnem);
                              },
                              _ => println!("unknown secret key")
                          }
                );
                //println!("Got raw secret cert {:#?}", secret);
                let cert_string = String::from_utf8(cert.as_tsk().armored().to_vec().expect("Could Not armor cert")).expect("Could not stringify cert");
                println!("Got a cert! {:#?}", cert_string);
                // TODO key restore
                // 1. subkeys for encryption and signing
                // 2. fingerprint
                // 3. comment
                // 4. passphrase salts
            },
            Err(err) => {
                println!("Error No Certs: {:#?}", err);
            }
        }
    }
}
