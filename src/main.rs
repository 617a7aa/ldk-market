#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() {
    use axum::Router;
    use ldk_node::Event;
    use leptos::*;
    use leptos_axum::{generate_route_list, LeptosRoutes};
    use leptos_test::{app::*, initialize_ecash_keys};
    use leptos_test::{NODE, db};
    std::thread::spawn(move || {
        println!("Node ID: {}", NODE.node_id());
        println!("Address: {}", NODE.onchain_payment().new_address().unwrap());
        println!("Channels: {:?}", NODE.list_channels());
        println!("Payments: {:?}", NODE.list_payments());
        println!("Funds: {:?}", NODE.list_balances());
        // connect to mutiny net node
        NODE.connect(
            "02465ed5be53d04fde66c9418ff14a5f2267723810176c9212b722e542dc1afb1b"
                .parse()
                .unwrap(),
            "45.79.52.207:9735".parse().unwrap(),
            true,
        )
        .unwrap();

        loop {
            let event = NODE.wait_next_event();
            println!("GOT NEW EVENT: {:?}", event);
            println!("Channels: {:?}", NODE.list_channels());
            println!("Payments: {:?}", NODE.list_payments());
            if let Event::PaymentReceived { payment_hash, .. } = event {
                println!("Payment received: {:?}", payment_hash);
                let deposits = db::thread_local_db().open_tree(TreeId::Deposits).unwrap();
                deposits.fetch_and_update(payment_hash.0, |old| {
                    if let Some(bytes) = old {
                        println!("Found an associated deposit, marking as paid.");
                        let mut new_bytes = bytes.to_vec();
                        new_bytes[0] = 1;
                        Some(new_bytes)
                    } else {
                        println!("No associated deposit found.");
                        None
                    }
                }).unwrap();
            }
            NODE.event_handled();
        }
    });

    initialize_ecash_keys();

    let conf = get_configuration(None).await.unwrap();
    let leptos_options = conf.leptos_options;
    let addr = leptos_options.site_addr;
    let routes = generate_route_list(App);

    // build our application with a route
    let app = Router::new()
        .leptos_routes(&leptos_options, routes, App)
        .fallback(leptos_test::fileserv::file_and_error_handler)
        .with_state(leptos_options);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    logging::log!("listening on http://{}", &addr);
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}

#[cfg(not(feature = "ssr"))]
pub fn main() {
    // no client-side main function
    // unless we want this to work with e.g., Trunk for a purely client-side app
    // see lib.rs for hydration function instead
}
