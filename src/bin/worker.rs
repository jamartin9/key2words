#[cfg(target_arch = "wasm32")]
use key2words::agent::MyWorker;
#[cfg(target_arch = "wasm32")]
use yew_agent::PublicWorker;

fn main() {
    #[cfg(target_arch = "wasm32")]
    MyWorker::register();
}
