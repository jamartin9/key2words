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
    let contents = "-----BEGIN PGP PRIVATE KEY BLOCK-----
Comment: 2552 388B 41BC 389C 39AD  1A76 1C73 B4B2 B695 0331
Comment: First Last test@example.org

xYYEYyTDKBYJKwYBBAHaRw8BAQdAegafDsVzfGff4SE025m+ubLOg4jMbtq3/4Tg
MudFasr+CQMIKFFrdGHJPQr/JBYKeAWje5M/c9I6iqxR6OmwZ9t5NW3+v6lIWvOS
xkz1OvQ0Od2GVv+89q1ZDt+7RojwvpZ6V5EEekmribBn3zFBYz3U4s0bRmlyc3Qg
TGFzdCB0ZXN0QGV4YW1wbGUub3JnwsAUBBMWCgCGBYJjJMMoBYkFn6YAAwsJBwkQ
HHO0sraVAzFHFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3Jn
nWP/iiPGCGhFke7K0T7RhMoK9XbGf+AqDsSEXhXg5jgDFQoIApkBApsBAh4BFiEE
JVI4i0G8OJw5rRp2HHO0sraVAzEAAN8jAQCiqqPcm6brbKWKHejaGb8RopIFC/rZ
yUG6kqc5kSYcDAD9HaU+YBehCD5HryrdMF3bBYe76p+R5BgrzpyHidH7cw3HiwRj
JMMoEgorBgEEAZdVAQUBAQdAMyqzwXg5kaI8fNPG5EzdG2aUVOu/3eE40S0mS1us
JCUDAQgH/gkDCH3MACIocz4b/3c3t0m8hPRFwIwq235bkR8zN9ZfFmJEfLlimUgB
YlfuyxQ40/CfPvAQ8TB6nuPxVKJRrTlM0KZZZkwFJqS4EjouXSvxPlLCwAYEGBYK
AHgFgmMkwygFiQWfpgAJEBxztLK2lQMxRxQAAAAAAB4AIHNhbHRAbm90YXRpb25z
LnNlcXVvaWEtcGdwLm9yZ0DqHGMPLi16MKtw7nWKbkMaPnunoOHTSqZWu+hKHEav
ApsIFiEEJVI4i0G8OJw5rRp2HHO0sraVAzEAAEDaAP4ms9nZR2eeu8s3nrOYW5jo
EYJ9AIkLshIBfG9pAlbWjgEAyALAOUQMfncSneyelI7WpbKinuj99WH2sx+ETJlx
6QE=
=Q+kR
-----END PGP PRIVATE KEY BLOCK-----
";
    //let contents = read_file_to_string("somefile.asc");
    let words = "jelly foam lemon section ecology rice menu renew page gallery genuine dice false plug stand cruise fortune exist rapid insect code shed coast hobby";
    let pass = Some("1234");
    let lang = Language::English;
    let (mnem, time, comment, duration) = convert_pgp_cert(&contents, lang, pass);
    assert_eq!(words, mnem.as_str());
    let cert = convert_pgp_mnem(words, lang, time, duration, &comment, pass);
    let (mnem_restored, time_restored, comment_restored, duration_restored) = convert_pgp_cert(cert.as_str(), lang, pass);
    assert_eq!(mnem_restored, mnem); // check fingerprint (mnem+ctime)
    assert_eq!(time_restored, time);
    assert_eq!(comment_restored, comment); // check userid
    assert_eq!(duration_restored, duration); // check validity
    assert_ne!(contents, cert); // salt should be different
}

use std::time::{SystemTime, Duration, UNIX_EPOCH};
// create pgp key from mnemonic
// MAYBE sign subkey for signing
// MAYBE sign user attributes
// MAYBE sign primary with self_signature
fn convert_pgp_mnem(words: &str, lang: Language, time: SystemTime, duration: Duration, user_id: &str, password: Option<&str>) -> String {
    let mnem = Mnemonic::from_phrase(words, lang).expect("Could not create mnemonic");
    let ent_slice: [u8; 32] = mnem.entropy()[..32]
        .try_into()
        .expect("Could not get entropy");
    let ed_kp = Ed25519Keypair::from_seed(&ent_slice);
    let ed_priv_key = ed_kp.private;

    // import primary key for ed25519 with fingerprint by setting ctime
    use sequoia_openpgp::packet::key::{Key4, SecretParts, PrimaryRole, SubordinateRole};
    use sequoia_openpgp::packet::prelude::*;
    use sequoia_openpgp::crypto::Password;
    use sequoia_openpgp::cert::prelude::*;

    let mut pgp_key: Key<SecretParts, PrimaryRole> = Key::from(Key4::import_secret_ed25519(&ed_priv_key.to_bytes(), time).expect("Failed to import key"));
    let mut keypair = pgp_key.clone().parts_into_secret().expect("failed to get secret").into_keypair().expect("failed to get keypair");
    if let Some(pass) = password { // encrypt with passphrase
        let secret: Password = pass.into();
        pgp_key.secret_mut().encrypt_in_place(&secret).expect("Failed to encrypt");
    }

    let sk = Packet::from(pgp_key);
    let cert = Cert::try_from(sk).expect("Could not get cert");

    // generate user id and binding signature
    use sequoia_openpgp::types::{HashAlgorithm, SignatureType, KeyFlags, SymmetricAlgorithm, Features};
    let userid = sequoia_openpgp::packet::UserID::from(user_id);
    let userid_keyflags = KeyFlags::empty().set_certification();
    let userid_builder = signature::SignatureBuilder::new(SignatureType::PositiveCertification);
    // set features of signature
    let sig = userid_builder.set_hash_algo(HashAlgorithm::SHA512).set_signature_creation_time(time).expect("Could not signature props");
    let mut sig = sig.set_features(Features::sequoia()).expect("no features")
            .set_key_flags(userid_keyflags).expect("no flags")
            .set_key_validity_period(duration).expect("no validity") // 157680000
            .set_preferred_hash_algorithms(vec![
                HashAlgorithm::SHA512,
                HashAlgorithm::SHA256,
            ]).expect("no hash algos")
            .set_preferred_symmetric_algorithms(vec![
                SymmetricAlgorithm::AES256,
                SymmetricAlgorithm::AES128,
            ]).expect("No aes");

    // mark as primary
    sig = sig.set_primary_userid(true).expect("could not mark primary");
    let binding = userid.bind(&mut keypair, &cert, sig).expect("Could not create binding");
    let cert = cert.insert_packets(vec![Packet::from(userid), binding.into()]).expect("Could not add userid");

    // ed25519 PublicKey is a CompressedEdwardsY in dalek.
    // Decompress to get a EdwardsPoint
    // Then translate Edwards to Montgomery for public key translation
    //
    // convert ed25519 private to x25519 by taking the first 32 bytes of its sha512 hash
    use sha2::{Digest, Sha512};
    // hash secret
    let hash = Sha512::digest(ed_priv_key.to_bytes());
    let mut output = [0u8; 32];
    output.copy_from_slice(&hash[..32]);
    let x25519_secret = x25519_dalek::StaticSecret::from(output);
    // import encryption secret subkey signed
    let mut aes_key: Key<_, SubordinateRole> = Key::from(Key4::import_secret_cv25519(&x25519_secret.to_bytes(), None, None, time).expect("Failed to import ecdh"));
    let aes_flags = KeyFlags::empty().set_storage_encryption();
    let aes_builder = signature::SignatureBuilder::new(SignatureType::SubkeyBinding)
        .set_hash_algo(HashAlgorithm::SHA512).set_signature_creation_time(time).expect("Could not set common flags")
        .set_key_flags(aes_flags).expect("Could not create aes sign builder")
        .set_key_validity_period(duration).expect("could not set valid period");
    let signature = aes_key.bind(&mut keypair, &cert, aes_builder).expect("Could not create aes binding");

    // encrypt with passphrase
    if let Some(pass) = password {
        let secret: Password = pass.into();
        aes_key.secret_mut().encrypt_in_place(&secret).expect("Failed to encrypt");
    }
    let cert = cert.insert_packets(vec![Packet::from(aes_key), signature.into()]).expect("could not add subkey");
    // generate cert
    /*let (cert, _rev) = CertBuilder::general_purpose(None, Some("user@example.com"))
        .set_password(Some("1234".into()))
        .add_storage_encryption_subkey()
        //.set_creation_time(time)
        .generate().expect("could not build cert");
    write_string_to_file(cert_string, "newest.asc");
    println!("Cert is {:#?}", cert); */
    use sequoia_openpgp::serialize::SerializeInto;
    let cert_string = String::from_utf8(cert.as_tsk().armored().to_vec().expect("Could Not armor cert")).expect("Could not stringify cert");
    cert_string
}

// Create  mneumonic from pgp key
// MAYBE return subkey(s) bytes
fn convert_pgp_cert(armored_private_key: &str, lang: Language, enc_key: Option<&str>) ->  (Zeroizing<String>, SystemTime, String, Duration) {
    let mut mnem_result = String::new();
    let mut comment = String::new();
    let mut ctime = UNIX_EPOCH;
    let mut duration = Duration::new(3 * 52 * 7 * 24 * 60 * 60, 0);

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
                use sequoia_openpgp::policy::StandardPolicy;
                let p = &StandardPolicy::new();
                // get the creation time
                ctime = secret.creation_time();
                // get the primary userid
                let vc = cert.with_policy(p, ctime).expect("could not get policy");
                let uid = vc.primary_userid().expect("could not get primary userid");
                comment = String::from_utf8(uid.value().to_vec()).expect("Could not parse uid");
                // get the cert duration
                duration = cert.primary_key().with_policy(p, ctime).expect("could not get primary key policy").key_validity_period().expect("could not get key valid period");
                //println!("Secret Cert is {:#?}", cert);
                // turn 32 secret key bytes into mnemonic
                use sequoia_openpgp::crypto::mpi::SecretKeyMaterial;
                let keypair = secret.into_keypair().expect("Failed to create keypair");
                let keypair_secret = keypair.secret();
                keypair_secret.map(|byte|
                          match byte {
                              SecretKeyMaterial::EdDSA{scalar} => {
                                  let mnem = Mnemonic::from_entropy(&scalar.value(), lang).expect("Failed to create mnemonic");
                                  mnem_result = mnem.phrase().to_string();
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
    (Zeroizing::new(mnem_result), ctime, comment, duration)
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
