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
    let words = "jelly foam lemon section ecology rice menu renew page gallery genuine dice false plug stand cruise fortune exist rapid insect code shed coast hobby";
    let contents = "-----BEGIN PGP PRIVATE KEY BLOCK-----
Comment: 2552 388B 41BC 389C 39AD  1A76 1C73 B4B2 B695 0331
Comment: user@example.com

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
05zXMxjoPuh+BF9S4fmGigk=
=ia0s
-----END PGP PRIVATE KEY BLOCK-----
";
    let lang = Language::English;
    //let contents = read_file_to_string("somefile.asc");
    let pass = Some("1234");
    let mnem = convert_pgp_cert(&contents, lang, pass);
    assert_eq!(words, mnem.as_str());
    // time
    use std::time::{UNIX_EPOCH, Duration};
    let time = UNIX_EPOCH + Duration::from_secs(1663353640);
    let cert = convert_pgp_mnem(words, lang, time);
    assert_eq!(contents, cert);
}
use std::time::SystemTime;
// create pgp key from mnemonic
fn convert_pgp_mnem(words: &str, lang: Language, time: SystemTime) -> String {
    let mnem = Mnemonic::from_phrase(words, lang).expect("Could not create mnemonic");
    let ent_slice: [u8; 32] = mnem.entropy()[..32]
        .try_into()
        .expect("Could not get entropy");
    let ed_kp = Ed25519Keypair::from_seed(&ent_slice);
    let ed_priv_key = ed_kp.private;
    // import key for ed25519
    use sequoia_openpgp::packet::key::{Key4, SecretParts, PrimaryRole};
    use sequoia_openpgp::packet::prelude::*;
    // fingerprint derived from ctime and private key bytes
    let pgp_key: Key<SecretParts, PrimaryRole> = Key::from(Key4::import_secret_ed25519(&ed_priv_key.to_bytes(), time).expect("Failed to import key"));
    println!("Fingerprint is {:#?}", pgp_key.fingerprint());
    use sequoia_openpgp::cert::prelude::*;
    let sk = Packet::from(pgp_key);
    // TODO: replicate gpg like structure
    // sign subkey for encryption
    // sign userID ComponentBundle
    // MAYBE sign subkey for signing
    // MAYBE sign user attributes
    // MAYBE sign primary with self_signature
    let cert = Cert::try_from(sk);
    println!("Cert is {:#?}", cert);
    // generate cert
    /*let (cert, _rev) = CertBuilder::general_purpose(None, Some("user@example.com"))
        .set_password(Some("1234".into()))
        .add_storage_encryption_subkey()
        //.set_creation_time(time)
        .generate().expect("could not build cert");// TODO reimplement variant of generate with subkeys
    use sequoia_openpgp::serialize::SerializeInto;
    let cert_string = String::from_utf8(cert.as_tsk().armored().to_vec().expect("Could Not armor cert")).expect("Could not stringify cert");
    write_string_to_file(cert_string, "newtest.asc");*/
    //cert_string
    String::new()
}

// Create  mneumonic from pgp key
fn convert_pgp_cert(armored_private_key: &str, lang: Language, enc_key: Option<&str>) ->  Zeroizing<String> {
    let mut result = String::new();
    use sequoia_openpgp::armor::{Reader, ReaderMode, Kind};
    let mut cursor = std::io::Cursor::new(&armored_private_key);
    let r = Reader::from_reader(&mut cursor, ReaderMode::Tolerant(Some(Kind::SecretKey)));

    // turn the reader into series of certs
    use sequoia_openpgp::parse::Parse;
    use sequoia_openpgp::cert::prelude::*;
    let cert_chain = CertParser::from_reader(r).expect("could not parse");
    for certs in cert_chain {
        match certs {
            Ok(cert) => {
                // get primary secret key
                let secret_key = cert.primary_key().key().clone().parts_into_secret().expect("Could not get secret key");
                // decrypt the secret key
                let secret = {
                    if ! secret_key.has_unencrypted_secret() {
                        if let Some(encryption_key) = enc_key {
                            secret_key.decrypt_secret(&encryption_key.into()).expect("Could not decrypt secret")
                        }else{
                            secret_key.decrypt_secret(&"Some such password".into()).expect("Could not decrypt secret with default password")
                        }
                    }else{
                        secret_key
                    }
                };
                //println!("Secret Cert is {:#?}", cert);
                let keypair = secret.into_keypair().expect("Failed to create keypair");
                let keypair_secret = keypair.secret();
                // turn 32 secret key bytes into mnemonic
                use sequoia_openpgp::crypto::mpi::SecretKeyMaterial;
                keypair_secret.map(|byte|
                          match byte {
                              SecretKeyMaterial::EdDSA{scalar} => {
                                  let mnem = Mnemonic::from_entropy(&scalar.value(), lang).expect("Failed to create mnemonic");
                                  result = mnem.phrase().to_string();
                                  //println!("Words are : {:#?}", mnem);
                                  // TODO include recreation info
                                  // 1. ctime
                                  // 2. return comment for user@email
                                  // 3. MAYBE return subkey(s) bytes
                                  // 4. MAYBE return fingerprint if generation is cumbersome
                              },
                              _ => println!("unknown secret key type")
                          }
                );
            },
            Err(err) => {
                println!("Error No Certs: {:#?}", err);
            }
        }
    }
    Zeroizing::new(result)
}
/* Helpers */
fn write_string_to_file(contents: String, file: &str) {
    let mut exported = std::fs::File::create(file).expect("Could not create file");
    use std::io::Write;
    exported.write_all(contents.as_bytes()).expect("Could not write file");
}

fn read_file_to_string(file: &str) -> String {
    use std::fs::File;
    use std::io::Read;
    let mut file = File::open(file).expect("No file found");
    let mut contents = String::new();
    file.read_to_string(&mut contents).expect("Could not read contents");
    contents
}
