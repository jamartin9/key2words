// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let _guard: Option<_> = {
        #[cfg(feature = "tracing-tauri")]
        {
            use tracing_chrome::ChromeLayerBuilder;
            use tracing_subscriber::prelude::*;
            let (chrome_layer, guard) = ChromeLayerBuilder::new().build();
            tracing_subscriber::registry().with(chrome_layer).init();
            Some(guard)
        }
        #[cfg(not(feature = "tracing-tauri"))]
        {
            None
        }
    };
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
