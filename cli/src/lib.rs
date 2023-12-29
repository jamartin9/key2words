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
        use console_subscriber::ConsoleLayer;
        let (chrome_layer, guard) = ChromeLayerBuilder::new().build(); // json traces
        let console_layer = ConsoleLayer::builder().retention(std::time::Duration::from_secs(30)).spawn(); // tokio-console watches port 6669

        tracing_subscriber::registry()
            .with(chrome_layer)
            .with(console_layer)
            .init();
        tracing::event!(Level::TRACE, "CLI EVENT");
        Some(guard)
    } else {
        None
    };

    #[cfg(feature = "yew-ssr")]
    if args.render {
        let renderer = yew::ServerRenderer::<App>::new();
        let html = renderer.render().await;
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 9001));
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        //use tower::{ServiceBuilder, ServiceExt, Service};
        use tower_http::services::ServeFile;
        use tower_http::trace::TraceLayer;
        let app = axum::Router::new()
            .nest_service("/key2words/app.js",ServeFile::new("dist/app.js"))
            .nest_service("/key2words/app_bg.wasm",ServeFile::new("dist/app_bg.wasm"))
            .nest_service("/key2words/bulma.0.9.4.min.css",ServeFile::new("dist/bulma.0.9.4.min.css"))
            .nest_service("/key2words/icon-16.png",ServeFile::new("dist/icon-16.png"))
            .nest_service("/key2words/icon-256.png",ServeFile::new("dist/icon-256.png"))
            .nest_service("/key2words/icon-32.png",ServeFile::new("dist/icon-32.png"))
            .nest_service("/key2words/manifest.json",ServeFile::new("dist/manifest.json"))
            .nest_service("/key2words/service_worker.js",ServeFile::new("dist/service_worker.js"))
            .nest_service("/key2words/worker.js",ServeFile::new("dist/worker.js"))
            .nest_service("/key2words/worker_bg.wasm",ServeFile::new("dist/worker_bg.wasm"))
            .nest_service("/key2words/", axum::routing::get(|| async {
                let index = tokio::fs::read_to_string("dist/index.html").await.expect("failed to read index.html");
                axum::response::Html(index) // TODO add ssr, use dir error handle, add config
            }));
        println!("{:#?}", html);
        axum::serve(listener, app.layer(TraceLayer::new_for_http()))
            .await
            .unwrap();
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

    Ok(())
}
