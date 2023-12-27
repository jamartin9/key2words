use anyhow::Result;
use bip39::Language;
use clap::{ArgGroup, Parser};
use key2words_core::{Converter, KeyConverter};
use std::{fmt::Debug, path::PathBuf};

#[cfg(feature = "yew-ssr")]
use key2words_web::App;

#[tracing::instrument]
fn write_to_file<T: AsRef<[u8]> + Debug>(contents: T, file: &str) -> Result<()> {
    let mut exported = std::fs::File::create(file)?;
    use std::io::Write;
    exported.write_all(contents.as_ref())?;
    Ok(())
}

/// Converts ed25519 keys using bip39
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(group(
            ArgGroup::new("mainopts")
                .required(true)
                .args(&["key", "words", "render"]),
        ))]
#[command(group(
            ArgGroup::new("either")
                .requires("mainopts")
                .conflicts_with_all(&["words", "ssh", "gpg", "comment", "epoch", "duration"])
                .args(&["key"]),
        ))]
struct Args {
    /// Path to the ed25519 private key of either ssh or gpg
    #[arg(short, long)]
    key: Option<PathBuf>,

    /// List of 24 space separated words
    #[arg(short, long)]
    words: Option<String>,

    /// comment for gpg/ssh key export
    #[arg(short, long)]
    comment: Option<String>,

    /// Generate ssh key
    #[arg(short, long)]
    ssh: bool,

    /// Generate tor key
    #[arg(short, long)]
    tor: bool,

    /// Generate pgp key
    #[arg(short, long)]
    gpg: bool,

    /// Encryption passphrase for private key
    #[arg(short, long)]
    pass: Option<String>,

    // Language for words ( en , es , ko , ja , it , fr , zh-hant , zh-hans )
    //#[clap(short, long)]
    //lang: Option<String>,
    /// Duration of key
    #[arg(short, long)]
    duration: Option<u64>,

    /// Creation time of key
    #[arg(short, long)]
    epoch: Option<u64>,

    #[cfg(feature = "yew-ssr")]
    /// Server side render app
    #[arg(short, long)]
    render: bool,

    #[cfg(feature = "tracing-cli")]
    /// Enable tracing (generates a trace-timestamp.json file).
    #[arg(long)]
    tracing: bool,
}

pub async fn cli() -> Result<()> {
    let args = Args::parse();

    #[cfg(feature = "tracing-cli")]
    let _guard = if args.tracing {
        use tracing::Level;
        use tracing_chrome::ChromeLayerBuilder;
        use tracing_subscriber::prelude::*;
        let (chrome_layer, guard) = ChromeLayerBuilder::new().build();
        tracing_subscriber::registry().with(chrome_layer).init();
        tracing::event!(Level::TRACE, "CLI EVENT");
        Some(guard)
    } else {
        None
    };
    #[cfg(feature = "yew-ssr")]
    if args.render {
        let renderer = yew::ServerRenderer::<App>::new();
        let html = renderer.render().await;
        println!("{:#?}", html);
    }
    // default to English
    let word_list_lang = Language::English;
    if let Some(wordlist) = args.words.as_deref() {
        let key_converter = KeyConverter::from_mnemonic(
            wordlist.to_string(),
            word_list_lang,
            args.comment,
            args.pass,
            args.epoch,
            args.duration,
        )?;
        if args.gpg {
            write_to_file(key_converter.to_pgp()?, "key.gpg")?;
        }
        if args.tor {
            write_to_file(key_converter.to_tor_address()?, "hostname")?;
            write_to_file(key_converter.to_tor_service()?, "hs_ed25519_secret_key")?;
            write_to_file(key_converter.to_tor_pub()?, "hs_ed25519_public_key")?;
        }
        if args.ssh {
            let (ssh_key, pub_key) = key_converter.to_ssh()?;
            write_to_file(pub_key, "id_ed25519.pub")?;
            write_to_file(ssh_key, "id_ed25519")?;
        }
    } else if let Some(keypath) = args.key {
        // check for .gpg and load as ssh otherwise
        let key_contents = std::fs::read_to_string(&keypath)?;
        let key_converter = {
            if "gpg" == keypath.extension().expect("Could not get extension") {
                KeyConverter::from_gpg(key_contents, args.pass, word_list_lang)?
            } else {
                KeyConverter::from_ssh(key_contents, args.pass, word_list_lang)?
            }
        };

        let words = key_converter.to_words()?;
        // print words/comment/ctime/duration
        println!("{}", words.as_str());
        println!("{}", key_converter.comment);
        println!("{:#?}", key_converter.duration);
        println!("{:#?}", key_converter.creation_time);
    }

    Ok(())
}
