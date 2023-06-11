use bip39::{Language, Mnemonic};
use ssh_key::private::{Ed25519Keypair, KeypairData};
use ssh_key::{rand_core::OsRng, LineEnding, PrivateKey};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

pub struct KeyConverter {
    ed_seed_secret: [u8; 32],
    lang: Language,
    pub comment: String, // MAYBE normalize ssh/pgp userid comments
    passphrase: Option<String>,
    pub creation_time: Option<SystemTime>,
    pub duration: Option<Duration>,
}

// TODO add result, error returns
// MAYBE investigate using HD keys from seed
pub trait Converter {
    fn to_words(&self) -> Zeroizing<String>;
    fn to_tor_service(&self) -> Vec<u8>;
    fn to_tor_pub(&self) -> Vec<u8>;
    fn to_tor_address(&self) -> String;
    fn to_pgp(&self) -> String;
    fn to_ssh(&self) -> (Zeroizing<String>, Zeroizing<String>); // (private, public)
    fn from_ssh(ssh: String, enc_key: Option<String>, lang: Language) -> Self;
    fn from_gpg(gpg: String, enc_key: Option<String>, lang: Language) -> Self;
    fn from_mnemonic(
        words: String,
        lang: Language,
        comment: Option<String>,
        enc_key: Option<String>,
        ctime: Option<u64>,
        duration: Option<u64>,
    ) -> Self;
}

impl Converter for KeyConverter {
    fn from_gpg(gpg: String, enc_key: Option<String>, lang: Language) -> KeyConverter {
        // MAYBE return subkey(s) bytes
        let mut mnem_result = String::new();
        let mut comment = String::new();
        let mut ctime = UNIX_EPOCH;
        let mut duration = Duration::new(3 * 52 * 7 * 24 * 60 * 60, 0);

        use sequoia_openpgp::armor::{Kind, Reader, ReaderMode};
        let mut cursor = std::io::Cursor::new(&gpg);
        let r = Reader::from_reader(&mut cursor, ReaderMode::Tolerant(Some(Kind::SecretKey)));

        // turn the reader into series of certs
        use sequoia_openpgp::cert::prelude::*;
        use sequoia_openpgp::parse::Parse;
        let cert_chain = CertParser::from_reader(r).expect("could not parse");
        for certs in cert_chain {
            match certs {
                Ok(cert) => {
                    // get primary secret key
                    let secret_key = cert
                        .primary_key()
                        .key()
                        .clone()
                        .parts_into_secret()
                        .expect("Could not get secret key");
                    // decrypt the secret key
                    let secret = {
                        if !secret_key.has_unencrypted_secret() {
                            if let Some(encryption_key) = enc_key.clone() {
                                secret_key
                                    .decrypt_secret(&encryption_key.into())
                                    .expect("Could not decrypt secret")
                            } else {
                                secret_key
                                    .decrypt_secret(&"Some such password".into())
                                    .expect("Could not decrypt secret with default password")
                            }
                        } else {
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
                    duration = cert
                        .primary_key()
                        .with_policy(p, ctime)
                        .expect("could not get primary key policy")
                        .key_validity_period()
                        .expect("could not get key valid period");
                    //println!("Secret Cert is {:#?}", cert);
                    // turn 32 secret key bytes into mnemonic
                    use sequoia_openpgp::crypto::mpi::SecretKeyMaterial;
                    let keypair = secret.into_keypair().expect("Failed to create keypair");
                    let keypair_secret = keypair.secret();
                    keypair_secret.map(|byte| match byte {
                        SecretKeyMaterial::EdDSA { scalar } => {
                            let mnem = Mnemonic::from_entropy_in(lang, scalar.value())
                                .expect("Failed to create mnemonic"); // MAYBE use raw bytes
                            mnem_result = mnem.to_string();
                        }
                        _ => println!("unknown secret key type"),
                    });
                }
                Err(err) => {
                    println!("Error No Certs: {:#?}", err);
                }
            }
        }
        let mnem =
            Mnemonic::parse_in(lang, mnem_result.as_str()).expect("Could not create mnemonic");
        // ignore the checksum byte
        let ent_slice: [u8; 32] = mnem.to_entropy()[..32]
            .try_into()
            .expect("Could not get entropy");
        KeyConverter {
            ed_seed_secret: ent_slice,
            lang,
            comment,
            passphrase: enc_key,
            creation_time: Some(ctime),
            duration: Some(duration),
        }
    }
    fn from_mnemonic(
        words: String,
        lang: Language,
        comment: Option<String>,
        enc_key: Option<String>,
        ctime: Option<u64>,
        duration: Option<u64>,
    ) -> KeyConverter {
        let mnem = Mnemonic::parse_in(lang, words.as_str()).expect("Could not create mnemonic");
        // ignore the checksum byte
        let ent_slice: [u8; 32] = mnem.to_entropy()[..32]
            .try_into()
            .expect("Could not get entropy");
        // xor entropy with hash of the enc_key bytes
        let secret = if let Some(xor_bytes) = &enc_key {
            use sha2::{Digest, Sha512_256};
            let mut hasher = Sha512_256::new();
            hasher.update(xor_bytes);
            let result = hasher.finalize();
            // xor secret with result
            ent_slice.iter().zip(result.iter()).map(|(s, r)| s ^ r).collect::<Vec<_>>().try_into().expect("Could not xor bytes")
        }else{
            ent_slice
        };
        let sys_time = ctime.map(|val| UNIX_EPOCH + Duration::from_secs(val));
        let dura = duration.map(|val| Duration::new(val, 0));
        KeyConverter {
            ed_seed_secret: secret,
            lang,
            comment: comment.unwrap_or_default(),
            passphrase: enc_key,
            creation_time: sys_time,
            duration: dura,
        }
    }
    fn from_ssh(ssh: String, enc_key: Option<String>, lang: Language) -> KeyConverter {
        let mut private_key = PrivateKey::from_openssh(ssh).expect("Failed to parse private key");
        if let Some(ref enc) = enc_key {
            // ignore non encrypted key
            if private_key.is_encrypted() {
                private_key = private_key.decrypt(enc).expect("Could not decrypt key");
            }
        }
        let ssh_comment = private_key.comment().to_owned();
        let key_pair = private_key
            .key_data()
            .ed25519()
            .expect("Failed to get ed25519 key");
        let priv_key = key_pair.private.to_owned();
        KeyConverter {
            ed_seed_secret: priv_key.to_bytes(),
            lang,
            comment: ssh_comment,
            passphrase: enc_key,
            creation_time: None,
            duration: None,
        }
    }
    fn to_words(&self) -> Zeroizing<String> {
        let ed_secret = &self.ed_seed_secret;
        // hash passphrase to get 32 xor_bytes
        let secret = if let Some(xor_bytes) = &self.passphrase {
            use sha2::{Digest, Sha512_256};
            let mut hasher = Sha512_256::new();
            hasher.update(xor_bytes);
            let result = hasher.finalize();
            // xor secret with result
            ed_secret.iter().zip(result.iter()).map(|(s, r)| s ^ r).collect::<Vec<_>>()
        }else{
            ed_secret.to_vec()
        };
        // turn into words
        let mnem = Mnemonic::from_entropy_in(self.lang, &secret)
            .expect("Failed to create mnemonic");
        Zeroizing::new(mnem.to_string())
    }
    fn to_tor_service(&self) -> Vec<u8> {
        use sha2::{Digest, Sha512};
        let mut hasher = Sha512::new();
        hasher.update(self.ed_seed_secret);
        let mut result = hasher.finalize(); // expanded secret key
                                            // clamp key for ed25519 spec
                                            // https://gitlab.torproject.org/dgoulet/torspec/blob/master/rend-spec-v3.txt#L2293
        result[0] &= 248;
        result[31] &= 63; // 127 (clamp like tor's key blinding)
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
    fn to_tor_pub(&self) -> Vec<u8> {
        // get ed25519 public key
        let ed_kp = Ed25519Keypair::from_seed(&self.ed_seed_secret);

        let pubkey = ed_kp.public.0;
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
    fn to_tor_address(&self) -> String {
        // concat checksum || pubkey || ver_byte into byte array
        // sha3.Sum256 sum the byte array
        // concat the publickey with the sha bytes then ver_byte
        // base32 encode result for onion address
        use base32ct::{Base32, Encoding};
        use sha3::{Digest, Sha3_256};
        let ed_kp = Ed25519Keypair::from_seed(&self.ed_seed_secret);

        let pubkey = ed_kp.public.0;
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
        #[cfg(target_os = "windows")]
        let line_ending = LineEnding::CRLF;
        #[cfg(not(target_os = "windows"))]
        let line_ending = LineEnding::LF;
        let mut hostname = Base32::encode_string(encode_me.as_slice());
        hostname.push_str(".onion");
        hostname.push_str(
            std::str::from_utf8(line_ending.as_bytes()).expect("Could not add line endings"),
        );
        hostname
    }
    fn to_ssh(&self) -> (Zeroizing<String>, Zeroizing<String>) {
        let ed_kp = Ed25519Keypair::from_seed(&self.ed_seed_secret);
        let mut restored_ssh_key = PrivateKey::new(KeypairData::from(ed_kp), &self.comment)
            .expect("Could not create ssh key");
        let public_ssh_key = restored_ssh_key
            .public_key()
            .to_openssh()
            .expect("Could not encode public key");
        if let Some(enc) = &self.passphrase {
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
    fn to_pgp(&self) -> String {
        // MAYBE create and sign subkey for signing
        // MAYBE sign user attributes
        // MAYBE sign primary with self_signature
        let time = self.creation_time.unwrap_or_else(SystemTime::now);
        let duration = self
            .duration
            .unwrap_or(Duration::new(3 * 52 * 7 * 24 * 60 * 60, 0));

        let ed_kp = Ed25519Keypair::from_seed(&self.ed_seed_secret);
        let ed_priv_key = ed_kp.private;

        // import primary key for ed25519 with fingerprint by setting ctime
        use sequoia_openpgp::cert::prelude::*;
        use sequoia_openpgp::crypto::Password;
        use sequoia_openpgp::packet::key::{PrimaryRole, SecretParts, SubordinateRole}; // Key4
        use sequoia_openpgp::packet::prelude::*;

        let mut pgp_key: Key<SecretParts, PrimaryRole> = Key::from(
            Key4::import_secret_ed25519(&ed_priv_key.to_bytes(), time)
                .expect("Failed to import key"),
        );
        let mut keypair = pgp_key
            .clone()
            .parts_into_secret()
            .expect("failed to get secret")
            .into_keypair()
            .expect("failed to get keypair");
        if let Some(pass) = &self.passphrase {
            // encrypt with passphrase
            let secret: Password = pass.as_str().into();
            pgp_key
                .secret_mut()
                .encrypt_in_place(&secret)
                .expect("Failed to encrypt");
        }

        let sk = Packet::from(pgp_key);
        let cert = Cert::try_from(sk).expect("Could not get cert");

        // generate user id and binding signature
        use sequoia_openpgp::types::{
            Features, HashAlgorithm, KeyFlags, SignatureType, SymmetricAlgorithm,
        };
        let userid = sequoia_openpgp::packet::UserID::from(self.comment.as_str());
        let userid_keyflags = KeyFlags::empty().set_certification();
        let userid_builder = signature::SignatureBuilder::new(SignatureType::PositiveCertification);
        // set features of signature
        let sig = userid_builder
            .set_hash_algo(HashAlgorithm::SHA512)
            .set_signature_creation_time(time)
            .expect("Could not signature props");
        let mut sig = sig
            .set_features(Features::sequoia())
            .expect("no features")
            .set_key_flags(userid_keyflags)
            .expect("no flags")
            .set_key_validity_period(duration)
            .expect("no validity") // 157680000
            .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512, HashAlgorithm::SHA256])
            .expect("no hash algos")
            .set_preferred_symmetric_algorithms(vec![
                SymmetricAlgorithm::AES256,
                SymmetricAlgorithm::AES128,
            ])
            .expect("No aes");

        // mark as primary
        sig = sig
            .set_primary_userid(true)
            .expect("could not mark primary");
        let binding = userid
            .bind(&mut keypair, &cert, sig)
            .expect("Could not create binding");
        let cert = cert
            .insert_packets(vec![Packet::from(userid), binding.into()])
            .expect("Could not add userid");

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
        // clamp
        output[0] &= 248; // clear lowest three bits of the first octet
        output[31] &= 127; // clear highest bit of the last octet
        output[31] |= 64; // set second highest bit of the last octet
        let x25519_secret = x25519_dalek::StaticSecret::from(output);
        // import encryption secret subkey signed
        let mut aes_key: Key<_, SubordinateRole> = Key::from(
            Key4::import_secret_cv25519(&x25519_secret.to_bytes(), None, None, time)
                .expect("Failed to import ecdh"),
        );
        let aes_flags = KeyFlags::empty().set_storage_encryption();
        let aes_builder = signature::SignatureBuilder::new(SignatureType::SubkeyBinding)
            .set_hash_algo(HashAlgorithm::SHA512)
            .set_signature_creation_time(time)
            .expect("Could not set common flags")
            .set_key_flags(aes_flags)
            .expect("Could not create aes sign builder")
            .set_key_validity_period(duration)
            .expect("could not set valid period");
        let signature = aes_key
            .bind(&mut keypair, &cert, aes_builder)
            .expect("Could not create aes binding");

        // encrypt with passphrase
        if let Some(pass) = &self.passphrase {
            let secret: Password = pass.as_str().into();
            aes_key
                .secret_mut()
                .encrypt_in_place(&secret)
                .expect("Failed to encrypt");
        }
        let cert = cert
            .insert_packets(vec![Packet::from(aes_key), signature.into()])
            .expect("could not add subkey");
        // generate cert
        /*let (cert, _rev) = CertBuilder::general_purpose(None, Some("user@example.com"))
            .set_password(Some("1234".into()))
            .add_storage_encryption_subkey()
            //.set_creation_time(time)
            .generate().expect("could not build cert");
        write_string_to_file(cert_string, "newest.asc");
        println!("Cert is {:#?}", cert); */
        use sequoia_openpgp::serialize::SerializeInto;
        let cert_string = String::from_utf8(
            cert.as_tsk()
                .armored()
                .to_vec()
                .expect("Could Not armor cert"),
        )
        .expect("Could not stringify cert");
        cert_string
    }
}

#[test]
fn test_convert_words(){
    let words = "render current master pear scrap hope mad mix pill penalty fresh mixture unaware armor lift million hard alley oppose pulse angry suspect element price";
    let lang = Language::English;
    let key_converter = KeyConverter::from_mnemonic(words.to_string(), lang, None, None, None, None);
    let converted_words = key_converter.to_words();
    assert_eq!(words, converted_words.as_str(), "Words are not equal without passphrase");
    let passphrased_words = "absurd alone hidden mail find trumpet enlist warrior cloud expose express quarter train section echo rice shine host waste gasp cool arrest hover local";
    let passphrase = Some("doggy".to_string());
    let key_converted_pass = KeyConverter::from_mnemonic(passphrased_words.to_string(), lang, None, passphrase, None, None);
    let converted_pass = key_converted_pass.to_words();
    assert_eq!(passphrased_words, converted_pass.as_str(), "Words are not equal with passphrase");
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
    let ssh_words = "absurd alone hidden mail find trumpet enlist warrior cloud expose express quarter train section echo rice shine host waste gasp cool arrest hover local"; //"render current master pear scrap hope mad mix pill penalty fresh mixture unaware armor lift million hard alley oppose pulse angry suspect element price";
    let lang = Language::English;
    let pass = Some("doggy".to_string());
    let key_converter = KeyConverter::from_ssh(ssh_key.to_string(), pass, lang);
    let mywords = key_converter.to_words();
    let comment = key_converter.comment.clone();
    let (restored_key, public_key) = key_converter.to_ssh();
    assert_eq!(ssh_pub, public_key.as_str(), "Public keys are not equal");
    assert_eq!(ssh_comment, comment.as_str(), "Comments are not equal");
    assert_eq!(ssh_words, mywords.as_str(), "Words are not equal");
    assert_ne!(ssh_key, restored_key.as_str(), "Encoded keys are equal"); // only in cases of collisions as encryption and pkdf should ensure uniqueness
}

#[test]
fn test_convert_tor() {
    let onion = "wm7k5436ulpxzkqbbxx55i2oeqpwl4nvfgspipwrimt7lrkkvnrkenid.onion\n"; // MAYBE test windows line endings
    let words = "render current master pear scrap hope mad mix pill penalty fresh mixture unaware armor lift million hard alley oppose pulse angry suspect element price";
    let lang = Language::English;
    let key_converter =
        KeyConverter::from_mnemonic(words.to_string(), lang, None, None, None, None);
    let onion_addr = key_converter.to_tor_address();
    let priv_key = key_converter.to_tor_service();
    let test_key = key_converter.to_tor_pub();

    assert_eq!(onion, onion_addr.as_str()); // .onion test

    use base64ct::{Base64, Encoding};
    let key = "PT0gZWQyNTUxOXYxLXNlY3JldDogdHlwZTAgPT0AAABo03+nGlb4tqVIsJnIbIoTBgbLnGHawsrS/y8fHbEXU0eTNWbCyfnM/DBnHbGg1+F72hm2XmxbTs7LmEjBE0tO";
    let encoded_key = Base64::encode_string(priv_key.as_slice());
    assert_eq!(key, encoded_key.as_str()); // private key test

    let pub_key =
        "PT0gZWQyNTUxOXYxLXB1YmxpYzogdHlwZTAgPT0AAACzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYg==";
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
    let words = "erase skill venture cruel usage wet trim snap cage sword orphan save uncover water clap toilet turn peasant language sample inherit chase recipe neglect"; //"jelly foam lemon section ecology rice menu renew page gallery genuine dice false plug stand cruise fortune exist rapid insect code shed coast hobby";
    let pass = Some("1234".to_string());
    let lang = Language::English;
    let key_converter = KeyConverter::from_gpg(contents.to_string(), pass.clone(), lang);
    let mnem = key_converter.to_words();
    let time = key_converter.creation_time.unwrap();
    let comment = key_converter.comment.clone();
    let duration = key_converter.duration.clone();
    let cert = key_converter.to_pgp();
    let restored_cert = cert.clone();
    let restored_key_converter = KeyConverter::from_gpg(cert, pass, lang);
    let mnem_restored = restored_key_converter.to_words();
    let time_restored = restored_key_converter.creation_time.unwrap();
    let comment_restored = restored_key_converter.comment.clone();
    let duration_restored = restored_key_converter.duration.clone();

    assert_eq!(words, mnem.as_str());
    assert_eq!(mnem_restored, mnem); // check fingerprint (mnem+ctime)
    assert_eq!(time_restored, time);
    assert_eq!(comment_restored, comment); // check userid
    assert_eq!(duration_restored, duration); // check validity
    assert_ne!(contents, restored_cert); // salt should be different
}
