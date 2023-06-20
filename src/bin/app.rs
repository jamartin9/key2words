#[cfg(target_arch = "wasm32")]
use key2words::web::App;

fn main() {
    #[cfg(target_arch = "wasm32")]
    yew::Renderer::<App>::new().render();
}
