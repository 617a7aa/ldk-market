#![feature(lazy_cell)]
#![allow(dead_code)]
pub mod app;
pub mod error_template;
pub mod hex;
#[cfg(feature = "ssr")]
pub mod fileserv;

use std::sync::LazyLock;
#[cfg(feature = "ssr")]
use ldk_node::Node;
#[cfg(feature = "ssr")]
pub static NODE: LazyLock<std::sync::Arc<Node>> = LazyLock::new(|| {
    use std::sync::Arc;

    use ldk_node::bitcoin::Network;
    use ldk_node::{default_config, Builder};

    let mut config = default_config();
    config.network = Network::Signet;
    config.listening_addresses = Some(vec![ldk_node::lightning::ln::msgs::SocketAddress::TcpIpV4 { addr: [127, 0, 0, 1], port: 9735 } ]);

    let mut builder = Builder::from_config(config);
    builder.set_esplora_server("https://mutinynet.com/api/".to_string());
    let node = Arc::new(builder.build().unwrap());
    node.start().unwrap();
    node
});

#[cfg(feature = "ssr")]
pub mod db {
    use std::rc::Rc;
    use std::sync::{Mutex, OnceLock};

    /// CELL is shared between ALL threads
    static CELL: OnceLock<Mutex<sled::Db>> = OnceLock::new();

    thread_local! {
        /// Thread local DB clone
        static DB: Rc<sled::Db> = Rc::new(CELL.get_or_init(|| {
            Mutex::new({
                let config = sled::Config { flush_every_ms: None, ..Default::default() };
                sled::Db::open_with_config(&config).unwrap()
            })
        }).lock().unwrap().clone());
    }

    /// thread_local_db returns a lazily initialised thread local clone of the
    /// database
    pub fn thread_local_db() -> Rc<sled::Db> {
        DB.with(|db| db.clone())
    }
}

#[cfg(feature = "ssr")]
pub fn initialize_ecash_keys() {
    use app::{CoreRng, TreeId, NOTE_VALUES};
    use blind_rsa_signatures::KeyPair;
    let db = db::thread_local_db();
    let key_tree = db.open_tree(TreeId::EcashKeys).unwrap();
    if key_tree.is_empty().unwrap() {
        for note_value in NOTE_VALUES {
            let sk = KeyPair::generate(&mut CoreRng::default(), 4096).unwrap().sk;
            key_tree.insert((note_value as u64).to_le_bytes(), sk.to_der().unwrap()).unwrap();
        }
    }
    db.flush().unwrap();
}

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    use crate::app::*;
    console_error_panic_hook::set_once();
    leptos::mount_to_body(App);
}
