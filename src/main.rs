use ssh_key::{PrivateKey};
use ssh_key::private::{Ed25519Keypair, Ed25519PrivateKey, KeypairData};
use ssh_key::public::{Ed25519PublicKey};
use ed25519_dalek::{SecretKey, PublicKey};
use base64ct::LineEnding;
use zeroize::Zeroizing;
use clap::{Parser,ArgGroup};


fn restore_openssh_key(words: &str, comment: &str) -> (Zeroizing<String>, String) {
    // create mnemonic from words
    let mnem = bip39::Mnemonic::parse_normalized(words).expect("Could not create mnemonic");
    // create private key from entropy
    let ent = mnem.to_entropy_array();
    let og: [u8 ;32] = ent.0[..32].try_into().expect("Could not get entropy");
    let og_pk = Ed25519PrivateKey(og);
    // create public key from private
    let og_pub : PublicKey = (&SecretKey::from_bytes(&og_pk.clone().into_bytes()).expect("Failure creating private key")).into();
    let restored_pub = Ed25519PublicKey(og_pub.as_bytes().to_owned());
    // create the ssh key from the keypair and comment
    let restored_keydata = KeypairData::Ed25519(Ed25519Keypair {
        private: og_pk, // TODO: constructor for bytes. needs pub on tuple patch
        public: restored_pub,
    });
    let restored_key = PrivateKey::new(restored_keydata, comment);
    let public_key = restored_key.public_key().to_openssh().expect("Could not encode public key");
    // TODO: windows support line endings
    (restored_key.to_openssh(LineEnding::LF).expect("Could not encode openssh key"), public_key)
}

fn create_restore_words(key: &str) -> (String, String) {
    // read private ssh key into bytes
    let private_key = PrivateKey::from_openssh(key).expect("Failed to parse private key");
    let comment = private_key.comment().to_owned();
    let key_pair = private_key.key_data().ed25519().expect("Failed to get ed25519 key");
    let priv_key = key_pair.private.to_owned();
    let mnem = bip39::Mnemonic::from_entropy(&priv_key.into_bytes()).expect("Failed to create mnemonic");
    (mnem.word_iter().collect::<Vec<&str>>().join(" "), comment)
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
            ArgGroup::new("wordsgroup")
                .requires("mainopts")
                .args(&["pubkey"]),
        ))]
#[clap(group(
            ArgGroup::new("keys")
                .conflicts_with("wordsgroup")
                .args(&["key"]),
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
}

fn main() {
    let args = Args::parse();
    if let Some(wordlist) = args.words.as_deref() {
        // parse comment from end of words
        let word_vec: Vec<&str> = wordlist.rsplitn(2, ' ').collect();
        let (restored_key, public_key) = restore_openssh_key(word_vec[1], word_vec[0]);
        if args.pubkey {
            println!("{}", public_key);
        }else{
            println!("{}",restored_key.as_str());
        }
    }else if let Some(keypath) = args.key {
        // TODO: encrypted key support
        let ssh_key = Zeroizing::new(std::fs::read_to_string(std::path::Path::new(&keypath)).expect("Invalid Path"));
        let (mut mywords, comment) = create_restore_words(ssh_key.as_str());
        mywords.push(' ');
        mywords.push_str(&comment);
        println!("{}",mywords);
    }
}

#[test]
fn test_convert_keys(){
    let ssh_key = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYgAAAJib9rtYm/a7
WAAAAAtzc2gtZWQyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYg
AAAEC2BsIi0QwW2uFscKTUUXNHLsYX4FxlaSDSblbAj7WR7bM+rvN+ot98qgEN796jTiQf
ZfG1KaT0PtFDJ/XFSqtiAAAAEHVzZXJAZXhhbXBsZS5jb20BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
"#;
    let ssh_pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti user@example.com";
    let ssh_comment = "user@example.com";
    let ssh_words = "render current master pear scrap hope mad mix pill penalty fresh mixture unaware armor lift million hard alley oppose pulse angry suspect element price";
    let (mywords, comment) = create_restore_words(ssh_key);
    let (restored_key, public_key) = restore_openssh_key(&mywords, &comment);
    assert_eq!(ssh_key, restored_key.as_str(), "Keys are not equal");
    assert_eq!(ssh_pub, public_key, "Public keys are not equal");
    assert_eq!(ssh_comment, comment, "Comments are not equal");
    assert_eq!(ssh_words, mywords, "Words are not equal");
}
