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
    /// Server side render app port
    #[arg(short, long)]
    render: Option<u16>,

    #[cfg(feature = "tracing-cli")]
    /// Enable tracing (generates a trace-timestamp.json file) and spawns tokio-console
    #[arg(long)]
    tracing: Option<u16>,
}

pub async fn cli() -> Result<()> {
    let args = Args::parse();

    #[cfg(feature = "tracing-cli")]
    let _guard = if args.tracing.is_some() {
        use console_subscriber::ConsoleLayer;
        use tracing_chrome::ChromeLayerBuilder;
        use tracing_subscriber::prelude::*;
        let (chrome_layer, guard) = ChromeLayerBuilder::new().build(); // json traces
        let console_layer = ConsoleLayer::builder()
            .server_addr(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                args.tracing.expect("No tokio-console port"),
            )))
            .retention(std::time::Duration::from_secs(60))
            .spawn();
        tracing_subscriber::registry()
            .with(chrome_layer)
            .with(console_layer)
            .init();
        println!(
            "tokio-console listening on port {}",
            args.tracing.expect("No tracing port")
        );
        Some(guard)
    } else {
        None
    };

    if let Some(wordlist) = args.words.as_deref() {
        // default to English
        let word_list_lang = Language::English;
        let key_converter = KeyConverter::from_mnemonic(
            wordlist.to_string(),
            word_list_lang,
            args.comment,
            args.pass,
            args.epoch,
            args.duration,
        )
        .await?;
        if args.gpg {
            write_to_file(key_converter.to_pgp().await?, "key.gpg")?;
        }
        if args.tor {
            write_to_file(key_converter.to_tor_address().await?, "hostname")?;
            write_to_file(
                key_converter.to_tor_service().await?,
                "hs_ed25519_secret_key",
            )?;
            write_to_file(key_converter.to_tor_pub().await?, "hs_ed25519_public_key")?;
        }
        if args.ssh {
            let (ssh_key, pub_key) = key_converter.to_ssh().await?;
            write_to_file(pub_key, "id_ed25519.pub")?;
            write_to_file(ssh_key, "id_ed25519")?;
        }
    } else if let Some(keypath) = args.key {
        // default to English
        let word_list_lang = Language::English;
        // check for .gpg and load as ssh otherwise
        let key_contents = std::fs::read_to_string(&keypath)?;
        let key_converter = {
            if "gpg" == keypath.extension().expect("Could not get extension") {
                KeyConverter::from_gpg(key_contents, args.pass, word_list_lang).await?
            } else {
                KeyConverter::from_ssh(key_contents, args.pass, word_list_lang).await?
            }
        };

        let words = key_converter.to_words().await?;
        // print words/comment/ctime/duration
        println!("{}", words.as_str());
        println!("{}", key_converter.comment);
        println!("{:#?}", key_converter.duration);
        println!("{:#?}", key_converter.creation_time);
    }

    #[cfg(feature = "yew-ssr")]
    if args.render.is_some() {
        use axum::{response, routing, serve, Router};
        use std::net::SocketAddr;
        use tokio::{fs::read_to_string, net::TcpListener};
        use tower_http::{services::ServeDir, trace::TraceLayer};
        // prepare yew app ssr response
        let renderer = yew::ServerRenderer::<App>::new();
        let html = renderer.render().await;
        let index = read_to_string("dist/index.html")
            .await
            .expect("failed to read index.html");
        let (index_html_before, index_html_after) = index.split_once("<body>").unwrap();
        let mut resp = index_html_before.to_owned();
        resp.push_str("<body>");
        resp.push_str(&html);
        resp.push_str(index_html_after);
        let resp = response::Html(resp);

        // setup server
        let addr = SocketAddr::from(([127, 0, 0, 1], args.render.expect("No Render port")));
        let listener = TcpListener::bind(addr).await.unwrap();
        let app = Router::new().nest_service(
            "/key2words/",
            ServeDir::new("dist")
                .append_index_html_on_directories(false)
                .fallback(routing::get(|| async { resp })),
        );
        println!(
            "Serving dist /key2words/ on port {}",
            args.render.expect("No render port")
        );
        serve(listener, app.layer(TraceLayer::new_for_http()))
            .await
            .unwrap();
    }

    Ok(())
}
#[test]
fn verify_cli() {
    use clap::CommandFactory;
    Args::command().debug_assert()
}
