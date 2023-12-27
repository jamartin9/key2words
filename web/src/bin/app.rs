use key2words_web::App;

fn main() {
    #[cfg(feature = "tracing-yew")]
    {
        use tracing_subscriber::{
            fmt::format::{FmtSpan, Pretty},
            prelude::*, filter::LevelFilter,
        };
        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .without_time()
            .with_writer(tracing_web::MakeWebConsoleWriter::new().with_pretty_level())
            .with_level(false)
            .with_span_events(FmtSpan::ACTIVE)
            .with_filter(LevelFilter::INFO);
        let perf_layer = tracing_web::performance_layer().with_details_from_fields(Pretty::default());
        tracing_subscriber::registry()
            .with(fmt_layer)
            .with(perf_layer)
            .init();
    }
    yew::Renderer::<App>::new().render();
}
