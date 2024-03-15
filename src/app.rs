#[cfg(feature = "ssr")]
use crate::db;
use cfg_if::cfg_if;
use image::io::Reader as ImageReader;
#[cfg(feature = "ssr")]
use ldk_node::bitcoin::hashes::{sha256, Hash as _};
use paste::paste;
use std::{
    collections::HashMap,
    io::{Cursor, Read as _, Write as _},
    str::FromStr,
};
use wasm_bindgen::JsCast as _;
use wasm_bindgen_futures::JsFuture;

use aes_gcm::{
    aead::{Aead, Nonce},
    AeadCore, AeadInPlace, Aes256Gcm, Key, KeyInit,
};
use argon2::Argon2;
use blake3::{hash, Hash, Hasher};
use derive_more::Display;
#[cfg(not(feature = "ssr"))]
use getrandom::getrandom;
use lightning_invoice::Bolt11Invoice;
use pqc_kyber::{
    decapsulate, derive as kb_derive, encapsulate_with_seed, keypair, PublicKey,
    KYBER_PUBLICKEYBYTES,
};
#[cfg(feature = "ssr")]
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};

use arrayref::array_ref;
use leptos_use::{signal_throttled, storage::use_local_storage, utils::FromToStringCodec};
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "ssr")]
use crate::NODE;
use crate::{
    error_template::{AppError, ErrorTemplate},
    hex::{bts, stb, stb_fixed},
};
use blind_rsa_signatures::{
    BlindSignature, Options as BlindingOptions, PublicKey as RsaPublicKey,
    Secret as BlindingSecret, SecretKey as RsaSecretKey, Signature as RsaSignature,
};
use js_sys::{ArrayBuffer, Uint8Array};
use leptos::{logging::log, *};
use leptos_hotkeys::prelude::*;
use leptos_meta::*;
use leptos_router::*;
use thaw::*;

// UI STUFF

#[component]
fn GlobalStyles(theme: ReadSignal<Theme>) -> impl IntoView {
    view! {
        <Body attr:style=move || {
            let theme = theme.get();
            format!(
                "background-color: {}; color: {}; font-size: {}; color-scheme: {}; margin: 0;",
                theme.common.background_color,
                theme.common.font_color,
                theme.common.font_size,
                theme.common.color_scheme,
            )
        }/>
    }
}

#[component]
fn Provider(children: Children) -> impl IntoView {
    let mut theme = Theme::dark();
    theme.common.font_family = "Berkeley Mono, monospace".to_string();
    theme.common.background_color = "#000".to_string();
    let theme = create_rw_signal(theme);
    view! {
        <GlobalStyles theme=theme.read_only()/>
        <ThemeProvider theme>
            <MessageProvider>
                <HotkeysProvider>
                    <LoadingBarProvider>
                    <AuthProvider>
                        {children()}
                    </AuthProvider>
                    </LoadingBarProvider>
                </HotkeysProvider>
            </MessageProvider>
        </ThemeProvider>
    }
}

#[component]
fn TheRouter(is_routing: ReadSignal<bool>) -> impl IntoView {
    let loading_bar = use_loading_bar();

    create_effect(move |_| {
        if is_routing.get() {
            loading_bar.start();
        } else {
            loading_bar.finish();
        }
    });

    view! {
        <Routes>
            <Route path="" view=HomePage/>
            <Route path="/listings" view=Listings/>
            <Route path="/listings/new" view=NewListing/>
            <Route path="/listings/:id" view=ListingPage/>
            <Route path="/deposit" view=Deposit/>
            <Route path="/withdraw" view=Withdraw/>
        </Routes>
    }
}

#[component]
fn NewListing() -> impl IntoView {
    let title = create_rw_signal(String::new());
    let description = create_rw_signal(String::new());
    let amount = create_rw_signal(0);
    let currency = create_rw_signal(Some(Currency::Bitcoin));
    let quantity = create_rw_signal(1);
    let condition = create_rw_signal(Some(Condition::New));

    let currency_options = vec![SelectOption {
        label: "Bitcoin".to_string(),
        value: Currency::Bitcoin,
    }];
    let condition_options = vec![
        SelectOption {
            label: "New".to_string(),
            value: Condition::New,
        },
        SelectOption {
            label: "Used".to_string(),
            value: Condition::Used,
        },
        SelectOption {
            label: "Refurbished".to_string(),
            value: Condition::Refurbished,
        },
    ];

    let message = use_message();

    let images = create_rw_signal::<Vec<(AttachmentId, Attachment)>>(vec![]);

    let progress_bar = create_rw_signal(0.0);

    let file_action = create_action(move |file_list: &FileList| {
        let file_list = file_list.clone();
        async move {
            for file_id in 0..file_list.length() {
                let file = file_list.get(file_id).unwrap();
                let buf: ArrayBuffer = JsFuture::from(file.array_buffer())
                    .await
                    .unwrap()
                    .dyn_into()
                    .unwrap();
                let data = Uint8Array::new(&buf).to_vec();
                let img = ImageReader::new(Cursor::new(data))
                    .with_guessed_format()
                    .unwrap()
                    .decode()
                    .unwrap();
                let mut webp: Vec<u8> = Vec::new();
                img.write_to(&mut Cursor::new(&mut webp), image::ImageFormat::WebP)
                    .unwrap();
                let attachment = Attachment(webp, AttachmentType::WebP);
                let id = AttachmentId(*hash(&attachment.0).as_bytes());
                images.update(move |images| {
                    images.push((id, attachment));
                });
            }
        }
    });

    let file_submitter = Callback::new(move |file_list: FileList| {
        file_action.dispatch(file_list);
    });

    let auth_state = use_context::<AuthState>().expect("an authstate to be provided");

    let create_listing_action = create_action(move |listing: &Listing| {
        let mut listing = listing.clone();
        async move {
            let mut key = [0u8; 32];
            let rng = &mut CoreRng::default();
            rng.fill_bytes(&mut key);
            let key_hash = KeyHash::from_key(&key);

            let id = ListingId::gen(rng);
            log!("encrypting {:?} with {:?}", id, key);
            let enc_id = id.encrypt(&key, rng);
            log!("{:?}", enc_id);

            let kc = auth_state.kc.get_untracked().expect("kc to be present");

            let pub_key = KyberPublicKey(kb_derive(&kc.master_seed).unwrap().public);

            let atts = images.get_untracked();
            log!("{:?}", atts.len());
            let total_atts = atts.len();

            for (i, (_, att)) in atts.into_iter().enumerate() {
                let enc_attachment = att.clone().encrypt_in_place(&key, &mut CoreRng::default());
                let id = upload_attachment(enc_attachment).await.unwrap().unwrap();
                listing.attachments.push(id);
                progress_bar.set((i + 1) as f32 / total_atts as f32 * 100.0);
            }

            let enc_listing = listing.encrypt(&key, rng);

            create_listing(id, enc_listing).await.unwrap();
            create_encrypted_listing_id(key_hash, enc_id).await.unwrap();
            let enc_key =
                EncryptedKey::from_key(&key, &kc.listing_encryption_keys_encryption_key, rng);
            create_encrypted_listing_key(pub_key, enc_key)
                .await
                .unwrap();
            message.create(
                "Created listing".to_owned(),
                MessageVariant::Success,
                Default::default(),
            );
            use_navigate()("/listings", Default::default());
        }
    });

    let on_click = Callback::new(move |_| {
        let listing = Listing {
            title: title.get_untracked(),
            description: description.get_untracked(),
            price: Price(amount.get_untracked(), currency.get_untracked().unwrap()),
            quantity: quantity.get_untracked(),
            condition: condition.get_untracked().unwrap(),
            attachments: vec![],
        };
        create_listing_action.dispatch(listing);
    });

    view! {
        <Space vertical=true gap=SpaceGap::Small>
            <Input value=title placeholder="Title"/>
            <Input value=description placeholder="Description"/>
            <InputNumber value=amount step=1 placeholder="Amount"/>
            <Select options=currency_options value=currency/>
            <InputNumber value=quantity step=1 placeholder="Quantity"/>
            <Select options=condition_options value=condition/>
            <Progress percentage=progress_bar show_indicator=false/>
            <Upload custom_request=file_submitter multiple=true accept=".jpg, .png, .webp, .gif, .tiff, .bmp">
            <UploadDragger>
                {move || if images.get().len() <= 1 {
                    view! { Add images }
                } else {
                    view! { Add more images }
                }}
            </UploadDragger>
            </Upload>
            <For
                // a function that returns the items we're iterating over; a signal is fine
                each=move || images.get()
                // a unique key for each item
                key=|(id, _)| *id
                // renders each item to a view
                children=move |(_, attachment)| {
                    let string_value = format!("data:{};base64,{}", attachment.1.to_mime(), base64::encode(&attachment.0));
                    view! {
                        <Image src=string_value height="200px"/>
                    }
                }
            />
            <Button on_click=on_click>Submit</Button>
        </Space>
    }
}

#[server(CreateListing)]
async fn create_listing(id: ListingId, listing: EncryptedListing) -> Result<(), ServerFnError> {
    let listings = db::thread_local_db().open_tree(TreeId::Listings).unwrap();
    listings.insert(&id.0, listing.0).unwrap();
    Ok(())
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
struct KeyHash(#[serde_as(as = "Base64")] [u8; 32]);

impl KeyHash {
    fn from_key(key: &[u8; 32]) -> Self {
        Self(*hash(key).as_bytes())
    }
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKey(#[serde_as(as = "Base64")] [u8; 32 + 16 + 12]);

impl EncryptedKey {
    fn from_key(key_to_encrypt: &[u8; 32], encryption_key: &[u8; 32], rng: &mut CoreRng) -> Self {
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from_slice(encryption_key));
        let nonce = Aes256Gcm::generate_nonce(rng);
        let encrypted = cipher.encrypt(&nonce, key_to_encrypt.as_ref()).unwrap();
        let mut enc_key = [0u8; 32 + 16 + 12];
        enc_key[..32 + 16].copy_from_slice(&encrypted);
        enc_key[32 + 16..].copy_from_slice(&nonce);
        Self(enc_key)
    }

    fn decrypt(self, decryption_key: &[u8; 32]) -> [u8; 32] {
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from_slice(decryption_key));
        let nonce_bytes = {
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes.copy_from_slice(&self.0[self.0.len() - 12..]);
            nonce_bytes
        };
        let nonce = Nonce::<Aes256Gcm>::from_slice(&nonce_bytes);
        let decrypted = cipher.decrypt(nonce, &self.0[..32 + 16]).unwrap();
        let mut key = [0u8; 32];
        key.copy_from_slice(&decrypted);
        key
    }
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KyberPublicKey(#[serde_as(as = "Base64")] pqc_kyber::PublicKey);

#[server(CreateEncryptedListingId)]
async fn create_encrypted_listing_id(
    key_hash: KeyHash,
    enc_listing_id: EncryptedListingId,
) -> Result<(), ServerFnError> {
    let encrypted_listing_ids = db::thread_local_db()
        .open_tree(TreeId::EncryptedListingIds)
        .unwrap();
    let mut key = [0u8; 32 + 32 + 16 + 12]; // enc key hash, encrypted listing id
    let mut cursor = Cursor::new(&mut key[..]);
    cursor.write_all(&key_hash.0).unwrap();
    cursor.write_all(&enc_listing_id.0).unwrap();
    encrypted_listing_ids.insert(key, &[]).unwrap();
    Ok(())
}

#[server(CreateEncryptedListingKey)]
async fn create_encrypted_listing_key(
    public_key: KyberPublicKey,
    enc_key: EncryptedKey,
) -> Result<(), ServerFnError> {
    let encrypted_keys = db::thread_local_db()
        .open_tree(TreeId::EncryptedListingKeys)
        .unwrap();
    let mut key = [0u8; KYBER_PUBLICKEYBYTES + 32 + 16 + 12];
    let mut cursor = Cursor::new(&mut key[..]);
    cursor.write_all(&public_key.0).unwrap();
    cursor.write_all(&enc_key.0).unwrap();
    encrypted_keys.insert(key, &[]).unwrap();
    Ok(())
}

#[server(GetEncryptedListingKeys)]
async fn get_encrypted_listing_keys(
    public_key: KyberPublicKey,
    page_size: u64,
    page: u64,
) -> Result<Vec<EncryptedKey>, ServerFnError> {
    let encrypted_keys = db::thread_local_db()
        .open_tree(TreeId::EncryptedListingKeys)
        .unwrap();
    let mut keys = vec![];
    let start = (page * page_size) as usize;
    let end = start + page_size as usize;
    for res in encrypted_keys
        .scan_prefix(&public_key.0)
        .skip(start)
        .take(end - start)
    {
        if let Ok((key, _)) = res {
            let mut cursor = Cursor::new(&key[KYBER_PUBLICKEYBYTES..]);
            let mut enc_key = [0u8; 32 + 16 + 12];
            cursor.read_exact(&mut enc_key).unwrap();
            let enc_key = EncryptedKey(enc_key);
            keys.push(enc_key);
        }
    }
    Ok(keys)
}

#[server(GetEncryptedListingIds)]
async fn get_encrypted_listing_ids(
    key_hash: KeyHash,
    page_size: u64,
    page: u64,
) -> Result<Vec<EncryptedListingId>, ServerFnError> {
    let encrypted_listing_ids = db::thread_local_db()
        .open_tree(TreeId::EncryptedListingIds)
        .unwrap();
    let mut ids = vec![];
    let start = (page * page_size) as usize;
    let end = start + page_size as usize;
    for res in encrypted_listing_ids
        .scan_prefix(&key_hash.0)
        .skip(start)
        .take(end - start)
    {
        if let Ok((key, _)) = res {
            let mut enc_id = [0u8; 32 + 16 + 12];
            enc_id.copy_from_slice(&key[key_hash.0.len()..]);
            let enc_id = EncryptedListingId(enc_id);
            ids.push(enc_id);
        }
    }
    Ok(ids)
}

#[server(GetEncryptedListings)]
async fn get_encrypted_listings(
    listing_ids: Vec<ListingId>,
) -> Result<Vec<Vec<u8>>, ServerFnError> {
    let mut listings = vec![];
    let listings_tree = db::thread_local_db().open_tree(TreeId::Listings).unwrap();
    for id in listing_ids {
        let listing = listings_tree.get(&id.0).unwrap().unwrap();
        listings.push(listing.to_vec());
    }
    Ok(listings)
}

#[component]
fn Deposit() -> impl IntoView {
    let amount = create_rw_signal(0);
    let have_invoice = create_rw_signal(false);
    let original_notes = create_rw_signal(None::<Vec<UnsignedNote>>);
    let blinded_notes = create_rw_signal(None::<Vec<BlindedNote>>);
    let secrets = create_rw_signal(None::<Vec<BlindingSecret>>);
    let auth_state = use_context::<AuthState>().expect("AuthState not found");

    let get_invoice = create_action(move |amount: &u64| {
        let amount = amount.clone();
        async move {
            let rng = &mut CoreRng::default();
            let note_values = break_down_amount_into_notes(amount);

            let registry_public_keys = get_registry_public_keys().await.unwrap();
            let mut pks = vec![];
            for (v, pk) in registry_public_keys {
                let key = RsaPublicKey::from_der(&pk).unwrap();
                pks.push((v, key));
            }
            pks.sort_by(|a, b| a.0.cmp(&b.0));
            let pks = pks.into_iter().map(|(v, pk)| pk).collect::<Vec<_>>();
            let registry_public_keys = RegistryPublicKeys(pks.try_into().unwrap());

            for note_value in note_values.iter() {
                let note = UnsignedNote::gen(*note_value, rng);

                original_notes.update(|vec| {
                    if let Some(vec) = vec {
                        vec.push(note.clone());
                    } else {
                        *vec = Some(vec![note.clone()]);
                    }
                });

                let (blinded_note, secret) = note.blind(&registry_public_keys, rng).unwrap();

                blinded_notes.update(|vec| {
                    if let Some(vec) = vec {
                        vec.push(blinded_note.clone());
                    } else {
                        *vec = Some(vec![blinded_note.clone()]);
                    }
                });

                secrets.update(|vec| {
                    if let Some(vec) = vec {
                        vec.push(secret.clone());
                    } else {
                        *vec = Some(vec![secret.clone()]);
                    }
                })
            }
            let bob = deposit(amount).await.unwrap();
            have_invoice.set(true);
            bob
        }
    });

    let payment_hash = create_memo(move |_| {
        get_invoice.value().get().map(|invoice| {
            Bolt11Invoice::from_str(&invoice)
                .unwrap()
                .payment_hash()
                .to_string()
        })
    });

    let on_click_get_invoice = Callback::new(move |_| {
        get_invoice.dispatch(amount.get_untracked());
    });

    let claim_deposit = create_action(move |_| {
        async move {
            let rng = &mut CoreRng::default();
            // get the registry's public keys
            let registry_public_keys = get_registry_public_keys().await.unwrap();
            let mut pks = vec![];
            for (v, pk) in registry_public_keys {
                let key = RsaPublicKey::from_der(&pk).unwrap();
                pks.push((v, key));
            }
            pks.sort_by(|a, b| a.0.cmp(&b.0));
            let pks = pks.into_iter().map(|(v, pk)| pk).collect::<Vec<_>>();
            let registry_public_keys = RegistryPublicKeys(pks.try_into().unwrap());

            // get the server to sign our nots
            let sigs = claim_deposit(
                payment_hash.get_untracked().unwrap(),
                blinded_notes.get_untracked().unwrap(),
            )
            .await
            .unwrap()
            .into_iter()
            // parse them
            .map(|sig| BlindSignature(stb(&sig).unwrap()))
            .collect::<Vec<_>>();
            let blinded_notes = blinded_notes.get_untracked().unwrap();
            let secrets = secrets.get_untracked().unwrap();
            let original_notes = original_notes.get_untracked().unwrap();
            let encryption_key = auth_state.kc.get_untracked().unwrap().ecash_encryption_key;
            // apply the signatures to all the notes and encrypt them
            let encrypted_signed_unblinded_notes = blinded_notes
                .into_iter()
                .enumerate()
                .map(|(i, note)| {
                    note.add_server_signature(
                        sigs[i].clone(),
                        &registry_public_keys,
                        original_notes[i].reference.clone(),
                        secrets[i].clone(),
                    )
                    .unwrap()
                    .encrypt(&encryption_key, rng)
                })
                .collect::<Vec<_>>();
            let my_pk = kb_derive(&auth_state.kc.get_untracked().unwrap().master_seed).unwrap().public;
            // upload the encrypted notes to the server
            upload_encrypted_ecash_notes(KyberPublicKey(my_pk), encrypted_signed_unblinded_notes).await.unwrap();
        }
    });

    let on_click_redeem_ecash = Callback::new(move |_| {
        claim_deposit.dispatch(());
    });

    view! {
        <h1>
            Deposit {move || amount.get()} sats into your account
        </h1>
        <InputNumber value=amount step=1/>
        <Button on_click=on_click_get_invoice>Get invoice</Button>
        {move || get_invoice.value().get().map(|invoice| view! { <pre>{invoice}</pre> })}
        {move || payment_hash.get().map(|i| view! { <pre>{i}</pre> })}
        {move || have_invoice.get().then(|| view! {
            <Button on_click=on_click_redeem_ecash>"I've paid the invoice"</Button>
        })}

    }
}

#[component]
fn Withdraw() -> impl IntoView {
    view! {}
}

#[component]
fn Listings() -> impl IntoView {
    let auth_state = use_context::<AuthState>().expect("an auth state to be provided");

    let listings = create_resource(auth_state.kc, move |kc| async move {
        if let Some(kc) = kc {
            log!("found kc");
            let pub_key = kb_derive(&kc.master_seed).unwrap().public;

            // Listing keys are stored encrypted by the user and start the listing discovery process
            let listing_keys = get_encrypted_listing_keys(KyberPublicKey(pub_key), 10000, 0)
                .await
                .expect("failed to get encrypted listing keys")
                .into_iter()
                .map(|key| key.decrypt(&kc.listing_encryption_keys_encryption_key))
                .collect::<Vec<_>>();

            log!("found {} listing keys", listing_keys.len());
            // we hash the keys to work out what listing ids they can decrypt
            let mut listing_key_hashes = Vec::new();
            for key in listing_keys {
                listing_key_hashes.push((KeyHash::from_key(&key), key));
            }

            // we retrieve the relevant encrypted listing ids and decrypt them using the associated key
            let mut listing_ids = HashMap::new();
            for (hash, key) in listing_key_hashes {
                let ids = get_encrypted_listing_ids(hash.clone(), 10000, 0)
                    .await
                    .expect("failed to get encrypted listing ids")
                    .into_iter()
                    .map(|id| id.decrypt(&key))
                    .collect::<Vec<_>>();
                listing_ids.insert(key, ids);
                log!("found {} encrypted listing ids", listing_ids.len());
            }

            let mut loaded_listings = vec![];
            for (key, ids) in listing_ids {
                // we fetch the encrypted listings associated with this key
                let listings = get_encrypted_listings(ids.clone())
                    .await
                    .expect("failed to get encrypted listings")
                    .into_iter()
                    .enumerate()
                    .map(|(i, listing)| (ids[i], EncryptedListing(listing).decrypt(&key)))
                    .collect::<Vec<_>>();
                // download any attachments and decrypt them
                for (id, listing) in listings {
                    let mut attachments = HashMap::new();
                    for att in &listing.attachments {
                        log!("downloading attachment {:?}", att);
                        let attachment = download_attachment(*att)
                            .await
                            .expect("failed to get attachment");
                        if let Some(attachment) = attachment {
                            log!("downloaded attachment {:?}", att);
                            attachments.insert(*att, attachment.decrypt_in_place(&key).unwrap());
                        } else {
                            log!("warning: couldn't find attachment");
                        }
                    }
                    loaded_listings.push((id, listing, attachments));
                }
            }
            loaded_listings
        } else {
            vec![]
        }
    });
    view! {
        <Suspense
                fallback=move || view! { <Spinner size=SpinnerSize::Tiny/> }
            >
                <Grid cols=3>
                {move || {
                    listings.get()
                        .map(|a| view! {
                            <For
                                each=move || a.clone()
                                key=|(id, ..)| *id
                                children=move |(_, listing, attachments)| {
                                    view! {
                                        <GridItem>
                                            <Card title=listing.title>
                                                <CardHeaderExtra slot>{move || listing.price.to_string()}</CardHeaderExtra>
                                                {move || {
                                                    if listing.attachments.len() > 0 {
                                                        attachments.get(&listing.attachments[0]).map(|attachment| {
                                                            let string_value = format!("data:{};base64,{}", attachment.1.to_mime(), base64::encode(&attachment.0));
                                                            view! { <Image src=string_value height="200px"/> }
                                                        })
                                                    } else {
                                                        None
                                                    }
                                                }}
                                                <Text>{listing.description}</Text>

                                                <CardFooter slot>"footer"</CardFooter>
                                            </Card>
                                        </GridItem>
                                    }
                                }
                            />
                        })
                }}
                </Grid>
            </Suspense>
    }
}

#[component]
fn ListingPage() -> impl IntoView {
    view! {}
}

#[component]
fn LayoutWrapper(children: Children) -> impl IntoView {
    let auth_state = use_context::<AuthState>().expect("an auth state to be provided");
    let balance = create_resource(auth_state.kc, move |kc| async move {
        if let Some(kc) = kc {
            let pk = KyberPublicKey(kb_derive(&kc.master_seed).unwrap().public);
            let encrypted_notes = download_encrypted_ecash_notes(pk)
                .await
                .unwrap()
                .into_iter()
                .map(|note| note.decrypt(&kc.ecash_encryption_key))
                .collect::<Vec<_>>();
            let balance: u64 = encrypted_notes.iter().map(|note| note.value as u64).sum();
            Some(balance)
        } else {
            None
        }
    });
    view! {
        <Layout has_sider=false>
            <Layout>
                <LayoutHeader style="display: flex; justify-content: space-between; padding: 1em; align-items: center;">
                        <A href="/"><strong>Market</strong></A>
                        <Space gap=SpaceGap::Medium>
                            <A href="/listings">Listings</A>
                            <A href="/listings/new">New listing</A>
                            <A href="/deposit">Deposit</A>
                            <A href="/withdraw">Withdraw</A>
                        </Space>
                        {move || match auth_state.kc.get() {
                            Some(_) => {
                                view! {
                                    <>
                                    <Space gap=SpaceGap::Medium>
                                        <Suspense fallback=|| view! { <Spinner size=SpinnerSize::Tiny/> }>
                                            {move || { balance.get().flatten().map(|balance| view! {
                                                <Text>{move || format!("Balance: {}", balance)}</Text>
                                            })}}
                                        </Suspense>

                                        <LogoutBtn/>
                                        <A href="/profile">
                                            <Avatar src="https://s3.bmp.ovh/imgs/2021/10/723d457d627fe706.jpg" round=true/>
                                        </A>
                                    </Space>
                                    </>
                                }
                            }
                            None => {
                                view! {
                                    <>
                                    <ButtonGroup>
                                        <Button
                                            on_click=move |_| auth_state.register_open.set(true)
                                            loading=auth_state.register_open
                                            disabled=auth_state.login_open
                                        >
                                            Register
                                        </Button>
                                        <Button
                                            variant=ButtonVariant::Outlined
                                            on_click=move |_| auth_state.login_open.set(true)
                                            loading=auth_state.login_open
                                            disabled=auth_state.register_open
                                        >
                                            Login
                                        </Button>
                                    </ButtonGroup>
                                    </>
                                }
                            }
                        }}
                </LayoutHeader>
                <Layout>
                    {children()}
                    <RegisterModal/>
                    <LoginModal/>
                </Layout>
            </Layout>
        </Layout>
    }
}

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();
    let (is_routing, set_is_routing) = create_signal(false);

    view! {
        <Title text="Welcome to Leptos"/>
        <Stylesheet href="/font.css"/>

        <Router
            fallback=|| {
                let mut outside_errors = Errors::default();
                outside_errors.insert_with_default_key(AppError::NotFound);
                view! { <ErrorTemplate outside_errors/> }.into_view()
            }
            set_is_routing
        >
            <Provider>
                <LayoutWrapper>
                    <TheRouter is_routing/>
                </LayoutWrapper>
            </Provider>
        </Router>
    }
}

fn derive_key<const OUT_LEN: usize>(seed: &[u8], ctx: &[u8]) -> [u8; OUT_LEN] {
    let mut output = [0u8; OUT_LEN];
    let mut hasher = Hasher::new();
    hasher.update(seed);
    hasher.update(ctx);
    hasher.finalize_xof().fill(&mut output);
    output
}

cfg_if! {
    if #[cfg(feature = "ssr")] {
        use rand::rngs::ThreadRng;
        pub type CoreRng = ThreadRng;
    } else if #[cfg(feature = "hydrate")] {
        #[derive(Default)]
        pub struct CoreRng;

        impl RngCore for CoreRng {
            fn next_u32(&mut self) -> u32 {
                let mut buf = [0u8; 4];
                getrandom(&mut buf).unwrap();
                u32::from_le_bytes(buf)
            }

            fn next_u64(&mut self) -> u64 {
                let mut buf = [0u8; 8];
                getrandom(&mut buf).unwrap();
                u64::from_le_bytes(buf)
            }

            fn fill_bytes(&mut self, dest: &mut [u8]) {
                getrandom(dest).unwrap();
            }

            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
                Ok(getrandom(dest).unwrap())
            }
        }

        impl CryptoRng for CoreRng {}
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Keychain {
    /// Argon2 hash of the user's password
    pwd_hash: [u8; 32],
    /// The master seed is randomly generated and used to derive all other keys.
    master_seed: [u8; 64],
    /// The profile key encrypts a user's profile, including their name, profile picture, and other public information.
    profile_key: [u8; 32],
    /// The auth token is the main authenticator to the API.
    /// This is used as an API token to authenticate the user as it is smaller than a PQ signature
    auth_token: [u8; 32],
    /// The listing encryption key is used to encrypt and decrypt listing keys stored on the server
    listing_encryption_keys_encryption_key: [u8; 32],
    /// Used to derive Kyber1024 keys to derive order encryption keys
    orders_seed: [u8; 64],
    /// Used to encrypt ecash notes stored on the server
    ecash_encryption_key: [u8; 32],
}

/// 64-byte encrypted seed, 16-byte tag, 12-byte nonce
type EncryptedMasterSeed = [u8; 64 + 16 + 12];

impl Keychain {
    const SALT: &'static [u8] = b"example salt";
    fn new(pwd: String) -> (Self, EncryptedMasterSeed) {
        let mut master_seed = [0u8; 64];
        let mut rng = CoreRng::default();
        rng.fill_bytes(&mut master_seed);

        let argon_ctx = Argon2::default();
        let mut pwd_hash = [0u8; 32];
        argon_ctx
            .hash_password_into(pwd.as_bytes(), Self::SALT, &mut pwd_hash)
            .unwrap();

        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from_slice(&pwd_hash));
        let nonce = Aes256Gcm::generate_nonce(rng);
        let mut encrypted_master_seed = cipher.encrypt(&nonce, &master_seed[..]).unwrap();
        encrypted_master_seed.extend_from_slice(nonce.as_ref());

        (
            Self::from_master_seed(master_seed, pwd_hash),
            encrypted_master_seed.try_into().unwrap(),
        )
    }

    fn load(pwd: String, encrypted_master_seed: EncryptedMasterSeed) -> Option<Self> {
        let argon_ctx = Argon2::default();
        let mut pwd_hash = [0u8; 32];
        argon_ctx
            .hash_password_into(pwd.as_bytes(), Self::SALT, &mut pwd_hash)
            .unwrap();

        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from_slice(&pwd_hash));
        let nonce = Nonce::<Aes256Gcm>::from_slice(&encrypted_master_seed[64 + 16..]);
        let seed = cipher
            .decrypt(&nonce, &encrypted_master_seed[0..64 + 16])
            .ok()?;

        if seed.len() != 64 {
            return None;
        }

        Some(Self::from_master_seed(seed.try_into().unwrap(), pwd_hash))
    }

    fn auth_token_from_pwd(pwd: String) -> [u8; 32] {
        let argon_ctx = Argon2::default();
        let mut pwd_hash = [0u8; 32];
        argon_ctx
            .hash_password_into(pwd.as_bytes(), Self::SALT, &mut pwd_hash)
            .unwrap();
        derive_key(&pwd_hash, b"root auth token (blake3 server)")
    }

    fn from_master_seed(master_seed: [u8; 64], pwd_hash: [u8; 32]) -> Self {
        Self {
            pwd_hash,
            master_seed,
            profile_key: derive_key(&master_seed, b"profile encryption key (aes-gcm-256)"),
            auth_token: derive_key(&pwd_hash, b"root auth token (blake3 server)"),
            orders_seed: derive_key(
                &master_seed,
                b"orders master seed (kyber1024 keygen client)",
            ),
            listing_encryption_keys_encryption_key: derive_key(
                &master_seed,
                b"listing encryption keys encryption key (aes-gcm-256)",
            ),
            ecash_encryption_key: derive_key(&master_seed, b"ecash encryption key (aes-gcm-256)"),
        }
    }

    fn profile_key(&self) -> &[u8; 32] {
        &self.profile_key
    }

    fn auth_token(&self) -> &[u8; 32] {
        &self.auth_token
    }

    fn orders_seed(&self) -> &[u8; 64] {
        &self.orders_seed
    }
}

// fn run_keygen(pwd: String, set_pw_hash: WriteSignal<String>) {
//     let mut rng = CoreRng;
//     let kc = Keychain::from_password(pwd);

//     // example merchant keypair
//     let merchant_keypair = keypair(&mut rng).unwrap();

//     // either party only needs their master seed to decrypt an order
//     // we'll provide our public key in the encrypted order to the merchant
//     let _orders_kp = kb_derive(kc.orders_seed()).unwrap();

//     let mut order = b"order data...".to_vec();
//     log!("order: {}", bts(&order));
//     let order_id = hash(&order);

//     // deterministic seed for order encryption
//     let order_encapsulation_seed = derive_key::<32>(kc.orders_seed(), order_id.as_bytes());
//     // we deterministically encapsulate a shared secret using the merchant's public key and the order
//     let (ct, order_encryption_key) =
//         encapsulate_with_seed(&merchant_keypair.public, &order_encapsulation_seed).unwrap();
//     log!("Order encryption key: {}", bts(&order_encryption_key));

//     // client encrypts order using order_encryption_key
//     let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from_slice(&order_encryption_key));
//     let nonce = Aes256Gcm::generate_nonce(&mut rng);
//     cipher.encrypt_in_place(&nonce, &ct, &mut order).unwrap();
//     log!("Encrypted order: {}", bts(&order));

//     // client sends ct + encrypted order to merchant
//     // platform signs a timestampted receipt and sends it to the merchant
//     // merchant decrypts ciphertext to get the shared secret
//     // order can then be decrypted using the shared secret
//     let shared_secret = decapsulate(&ct, &merchant_keypair.secret).unwrap();
//     assert_eq!(shared_secret, order_encryption_key);
//     log!("Shared secret: {}", bts(&shared_secret));

//     cipher.decrypt_in_place(&nonce, &ct, &mut order).unwrap();
//     log!("Decrypted order: {}", bts(&order));

//     set_pw_hash(bts(&kc.master_seed));
// }

#[component]
fn AuthProvider(children: Children) -> impl IntoView {
    let local_tab_logged_in = create_rw_signal(false);
    let login_open = create_rw_signal(false);
    let register_open = create_rw_signal(false);
    let (username, set_username, _) = use_local_storage::<String, FromToStringCodec>("username");
    let local_tab_wants_logout = create_rw_signal(false);
    let (storage_wants_logout, set_storage_wants_logout, _) =
        use_local_storage::<bool, FromToStringCodec>("logout");
    let kc: RwSignal<Option<Keychain>> = create_rw_signal(None);

    provide_context(AuthState {
        local_tab_logged_in: local_tab_logged_in.read_only(),
        login_open,
        register_open,
        username,
        set_username,
        local_tab_wants_logout,
        storage_wants_logout,
        set_storage_wants_logout,
        kc,
    });

    let (browser_master_seed, set_browser_master_seed, _) =
        use_local_storage::<String, FromToStringCodec>("master_seed");

    let message = use_message();

    create_effect(move |_| {
        let should_logout = local_tab_wants_logout.get() || storage_wants_logout.get();

        let stored_seed = stb_fixed::<96>(&browser_master_seed.get());
        let kc_seed = kc.get().map(|kc| {
            let mut stored_data = [0u8; 96];
            stored_data[..64].copy_from_slice(&kc.master_seed);
            stored_data[64..].copy_from_slice(&kc.pwd_hash);
            stored_data
        });

        if should_logout && local_tab_logged_in.get() {
            log!("Logging out");
            if local_tab_wants_logout.get() {
                set_storage_wants_logout(true);
                set_browser_master_seed("".to_owned());
            }
            kc.set(None);
            message.create(
                "Logged out".to_owned(),
                MessageVariant::Success,
                Default::default(),
            );
            local_tab_logged_in.set(false);
            local_tab_wants_logout.set(false);
            set_username("".to_owned());
            return;
        }

        if kc_seed != stored_seed {
            match (kc_seed, stored_seed) {
                (Some(_), Some(_)) => {
                    log!("Reactivity system and local storage out of sync");
                }
                (None, Some(stored_seed)) => {
                    log!("Restoring master seed & pwd hash from local storage");
                    let master_seed = {
                        let mut seed = [0u8; 64];
                        seed.copy_from_slice(&stored_seed[0..64]);
                        seed
                    };
                    let pwd_hash = {
                        let mut pwd_hash = [0u8; 32];
                        pwd_hash.copy_from_slice(&stored_seed[64..96]);
                        pwd_hash
                    };
                    kc.set(Some(Keychain::from_master_seed(master_seed, pwd_hash)));
                    local_tab_logged_in.set(true);
                    set_storage_wants_logout(false);
                    login_open.set(false);
                    register_open.set(false);
                }
                (Some(kc_seed), None) => {
                    log!("Saving master seed & pwd hash to local storage");
                    set_browser_master_seed(bts(&kc_seed));
                    local_tab_logged_in.set(true);
                    set_storage_wants_logout(false);
                    login_open.set(false);
                    register_open.set(false);
                }
                _ => {}
            }
        }
    });

    children()
}

#[derive(Copy, Clone, Debug)]
struct AuthState {
    /// Whether or not the local tab is logged in
    local_tab_logged_in: ReadSignal<bool>,
    /// Whether or not the login modal is open
    login_open: RwSignal<bool>,
    /// Whether or not the register modal is open
    register_open: RwSignal<bool>,
    /// Browser-wide read-only username
    username: Signal<String>,
    /// Browser-wide write-only username
    set_username: WriteSignal<String>,
    /// Whether or not the local tab wants to log out
    local_tab_wants_logout: RwSignal<bool>,
    /// Whether or not the local storage wants to log out
    storage_wants_logout: Signal<bool>,
    /// Whether or not the local storage wants to log out
    set_storage_wants_logout: WriteSignal<bool>,
    /// The keychain
    kc: RwSignal<Option<Keychain>>,
}

#[component]
fn HomePage() -> impl IntoView {
    let (count, set_count) = create_signal(1);
    let on_click = move |_| {
        log!("Updating count");
        set_count.update(|count| *count += 1);
    };
    let slow_resource = create_resource(count, move |_| slow_task());

    view! {
        <Button
            variant=ButtonVariant::Primary
            on_click
            loading=slow_resource.loading()
            icon=icondata::AiCloseOutlined
        >
            Click to do something slow
        </Button>
        <p>
            Response:
            <Suspense fallback=|| {
                view! { loading... }
            }>{move || { slow_resource.get().map(|_| view! { done! }) }}</Suspense>
        </p>
        <Avatar
            src="https://s3.bmp.ovh/imgs/2021/10/723d457d627fe706.jpg"
            round=true
        />

        <Grid cols=4 x_gap=16>
            <GridItem>
                <Card title="title">
                    <Image
                        src="https://s3.bmp.ovh/imgs/2021/10/2c3b013418d55659.jpg"
                        width="100%"
                    />
                    <CardFooter slot>
                        <Button variant=ButtonVariant::Primary>"Add to order"</Button>
                    </CardFooter>
                </Card>
            </GridItem>
            <GridItem>
                <Card title="title">
                    <Image
                        src="https://s3.bmp.ovh/imgs/2021/10/2c3b013418d55659.jpg"
                        width="100%"
                    />
                </Card>
            </GridItem>
        </Grid>
    }
}

#[component]
fn LogoutBtn() -> impl IntoView {
    let auth_state = use_context::<AuthState>().expect("an auth state to be provided");
    view! { <Button variant=ButtonVariant::Text on_click=move |_| auth_state.local_tab_wants_logout.set(true)>Log out</Button> }
}

#[component]
fn RegisterModal() -> impl IntoView {
    let auth_state = use_context::<AuthState>().expect("an auth state to be provided");
    let username = create_rw_signal(String::from(""));
    let password = create_rw_signal(String::from(""));
    let throttled_username = signal_throttled(username, 500.0);
    let username_not_available = create_rw_signal(false);
    create_resource(throttled_username, move |username| async move {
        let res = is_username_available(username).await.unwrap();
        log!("Username available: {res}");
        username_not_available.set(!res);
    });

    let message = use_message();

    let temporary_kc = create_rw_signal(None);

    let register_account = create_server_action::<Register>();

    create_resource(register_account.pending(), move |pending| async move {
        if pending {
            return;
        }

        let options = MessageOptions::default();

        match register_account.value().get() {
            Some(Ok(_)) => {
                message.create(
                    "Registered account".to_owned(),
                    MessageVariant::Success,
                    options,
                );
                auth_state.register_open.set(false);
                auth_state.set_username.set(username.get_untracked());
                temporary_kc.update(|tkc| {
                    auth_state
                        .kc
                        .set(Some(tkc.take().expect("temporary kc to be set")))
                });
                username.set(String::from(""));
                password.set(String::from(""));
            }
            Some(Err(e)) => {
                message.create(
                    "Failed to register account".to_owned(),
                    MessageVariant::Error,
                    options,
                );
                log!("Error registering account: {e}");
            }
            None => {}
        }
    });

    let input_ref = create_component_ref::<InputRef>();
    create_effect(move |_| {
        if auth_state.register_open.get() {
            input_ref.get_untracked().unwrap().focus();
        }
    });

    let on_click = Callback::new(move |_| {
        let (temp_kc, encrypted_master_seed) = Keychain::new(password.get_untracked());
        temporary_kc.set(Some(temp_kc.clone()));
        let auth_token = *temp_kc.auth_token();
        register_account.dispatch(Register {
            username: username.get_untracked(),
            bin_params: RegisterBinaryParams {
                auth_token,
                encrypted_master_seed,
            },
        });
    });

    view! {
        <Modal title="Register account" show=auth_state.register_open>
            <Space vertical=true>
                <Input
                    value=username
                    placeholder="Username"
                    invalid=username_not_available
                    comp_ref=input_ref
                />
                {move || match username_not_available.get() {
                    true => Some(view! { <small>Username not available</small> }),
                    false => None,
                }}

                <Input value=password variant=InputVariant::Password placeholder="Password"/>
                <Button on_click loading=register_account.pending() disabled=username_not_available>
                    Register
                </Button>
            </Space>
        </Modal>
    }
}

#[component]
fn LoginModal() -> impl IntoView {
    let auth_state = use_context::<AuthState>().expect("an auth state to be provided");
    let username = create_rw_signal(String::from(""));
    let password = create_rw_signal(String::from(""));

    let message = use_message();

    let username_ref = create_component_ref::<InputRef>();
    let password_ref = create_component_ref::<InputRef>();
    create_effect(move |_| {
        if auth_state.login_open.get() {
            username_ref.get_untracked().unwrap().focus();
        }
    });

    let get_master_seed = create_server_action::<GetMasterSeed>();

    create_resource(get_master_seed.pending(), move |pending| async move {
        if pending {
            return;
        }
        let options = MessageOptions::default();
        let res = get_master_seed.value().get_untracked().map(|res| {
            res.map(|res| {
                res.0
                    .map(|ems| Keychain::load(password.get_untracked(), ems))
            })
        });

        let process = |res| match res {
            Ok(Some(Some(kc))) => {
                message.create(
                    "Logged in".to_owned(),
                    MessageVariant::Success,
                    Default::default(),
                );
                auth_state.login_open.set(false);
                log!("Setting username to {}", username.get_untracked());
                auth_state.set_username.set(username.get_untracked());
                auth_state.kc.set(Some(kc));
                username.set(String::from(""));
                password.set(String::from(""));
            }
            Ok(Some(None)) => {
                message.create(
                    "Couldn't derive keychain".to_owned(),
                    MessageVariant::Error,
                    options,
                );
                password.set(String::from(""));
                password_ref.get_untracked().unwrap().focus();
            }
            Ok(None) => {
                message.create("Wrong password".to_owned(), MessageVariant::Error, options);
                password.set(String::from(""));
                password_ref.get_untracked().unwrap().focus();
            }
            Err(e) => {
                message.create(
                    "Failed to check password".to_owned(),
                    MessageVariant::Error,
                    options,
                );
                log!("Error checking password: {e}");
            }
        };

        res.map(process);
    });

    let on_click = Callback::new(move |_| {
        let auth_token = Keychain::auth_token_from_pwd(password.get_untracked());
        let username = username.get_untracked();
        get_master_seed.dispatch(GetMasterSeed {
            username,
            auth_token,
        });
    });

    view! {
        <Modal title="Login to account" show=auth_state.login_open>
            <Space vertical=true>
                <Input value=username placeholder="Username" comp_ref=username_ref disabled=get_master_seed.pending()/>
                <Input value=password variant=InputVariant::Password placeholder="Password" comp_ref=password_ref disabled=get_master_seed.pending()/>
                <Button on_click loading=get_master_seed.pending()>
                    Login
                </Button>
            </Space>
        </Modal>
    }
}

#[server(SlowTask)]
pub async fn slow_task() -> Result<(), ServerFnError> {
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    Ok(())
}

#[derive(Debug, Display, Clone, PartialEq, Eq)]
pub enum ServerError {
    UsernameExists,
}

impl FromStr for ServerError {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "UsernameExists" => Ok(ServerError::UsernameExists),
            _ => Err(()),
        }
    }
}

#[server(IsUsernameAvailable)]
pub async fn is_username_available(username: String) -> Result<bool, ServerFnError> {
    let db = db::thread_local_db();
    let auth_tokens = db.open_tree(TreeId::AuthTokens)?;
    Ok(!auth_tokens.contains_key(&username)?)
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegisterBinaryParams {
    #[serde_as(as = "Base64")]
    /// Auth token
    auth_token: [u8; 32],
    /// Encrypted master seed
    #[serde_as(as = "Base64")]
    encrypted_master_seed: EncryptedMasterSeed,
}

#[server(Register)]
pub async fn register(
    username: String,
    bin_params: RegisterBinaryParams,
) -> Result<(), ServerFnError<ServerError>> {
    let db = db::thread_local_db();
    let auth_tokens = db.open_tree(TreeId::AuthTokens).unwrap();
    let encrypted_master_seeds = db.open_tree(TreeId::EncryptedMasterSeeds).unwrap();

    let RegisterBinaryParams {
        auth_token,
        encrypted_master_seed,
    } = bin_params;

    let salt = rand::thread_rng().gen::<[u8; 32]>();
    let mut hasher = Hasher::new();
    hasher.update(&salt);
    hasher.update(&auth_token);
    let pw_hash = hasher.finalize();

    let mut stored_auth_token = [0u8; 64];
    stored_auth_token[..32].copy_from_slice(&salt);
    stored_auth_token[32..].copy_from_slice(pw_hash.as_bytes());

    match auth_tokens.compare_and_swap::<_, &[u8], _>(&username, None, Some(&stored_auth_token)) {
        Ok(Err(_)) => Err(ServerError::UsernameExists)?,
        Err(e) => Err(ServerFnError::ServerError(e.to_string()))?,
        _ => {}
    }

    encrypted_master_seeds
        .insert(&username, &encrypted_master_seed)
        .expect("Failed to insert master seed");

    println!("Registered new user: {}", username);
    Ok(())
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GetMasterSeedResponse(#[serde_as(as = "Option<Base64>")] Option<EncryptedMasterSeed>);

#[server(GetMasterSeed)]
pub async fn get_master_seed(
    username: String,
    auth_token: [u8; 32],
) -> Result<GetMasterSeedResponse, ServerFnError> {
    if !check_auth_token(username.clone(), auth_token).await? {
        return Ok(GetMasterSeedResponse(None));
    }

    let db = db::thread_local_db();
    let encrypted_master_seeds = db.open_tree(TreeId::EncryptedMasterSeeds)?;

    Ok(GetMasterSeedResponse(
        encrypted_master_seeds.get(&username)?.map(|ems_db| {
            let mut ems: EncryptedMasterSeed = [0u8; 92];
            ems.copy_from_slice(&ems_db);
            ems
        }),
    ))
}

#[server(UploadAttachment)]
pub async fn upload_attachment(
    attachment: EncryptedAttachment,
    // we'll add some sort of validation later
) -> Result<Option<AttachmentId>, ServerFnError> {
    if attachment.0.len() > EncryptedAttachment::MAX_SIZE_BYTES {
        return Ok(None);
    }
    let attachments = db::thread_local_db().open_tree(TreeId::Attachments)?;
    let id = AttachmentId(*hash(&attachment.0).as_bytes());
    attachments
        .compare_and_swap(id.clone(), None::<&[u8]>, Some(attachment.0))?
        .unwrap();
    Ok(Some(id))
}

#[server(DownloadAttachment)]
pub async fn download_attachment(
    id: AttachmentId,
) -> Result<Option<EncryptedAttachment>, ServerFnError> {
    let attachments = db::thread_local_db().open_tree(TreeId::Attachments)?;
    Ok(attachments
        .get(&id)
        .unwrap()
        .map(|a| EncryptedAttachment(a.to_vec())))
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChangeMasterSeedParams {
    pub username: String,
    #[serde_as(as = "Base64")]
    pub auth_token: [u8; 32],
    #[serde_as(as = "Base64")]
    pub new_ems: EncryptedMasterSeed,
}

#[server(ChangeMasterSeed)]
pub async fn change_master_seed(params: ChangeMasterSeedParams) -> Result<bool, ServerFnError> {
    if !check_auth_token(params.username.clone(), params.auth_token).await? {
        return Ok(false);
    }

    let db = db::thread_local_db();
    let encrypted_master_seeds = db.open_tree(TreeId::EncryptedMasterSeeds)?;

    encrypted_master_seeds
        .insert(&params.username, &params.new_ems)
        .expect("Failed to insert master seed");
    Ok(true)
}

#[server(CheckAuthToken)]
/// Mostly used for internal purposes, maybe make properly private later if not needed?
pub async fn check_auth_token(
    username: String,
    auth_token: [u8; 32],
) -> Result<bool, ServerFnError> {
    let db = db::thread_local_db();
    let auth_tokens = db.open_tree(TreeId::AuthTokens)?;

    let stored_auth_token = auth_tokens.get(&username)?;

    if let Some(stored_auth_token) = stored_auth_token {
        if stored_auth_token.len() != 64 {
            return Err(ServerFnError::ServerError(
                "Invalid stored auth token".to_string(),
            ));
        }
        let (salt, stored_pw_hash) = stored_auth_token.split_at(32);
        let stored_pw_hash = Hash::from_bytes(*array_ref!(stored_pw_hash, 0, 32));
        let mut hasher = Hasher::new();
        hasher.update(salt);
        hasher.update(&auth_token);
        let pw_hash = hasher.finalize();
        Ok(stored_pw_hash == pw_hash)
    } else {
        return Ok(false);
    }
}

/// An enum that enforces the use of the correct tree for a given operation
pub enum TreeId {
    /// Username -> hashed auth token
    ///
    /// Used for verifying API requests
    AuthTokens,
    /// Username -> EncryptedMasterSeed
    ///
    /// Used for storing encrypted master seeds, allowing user to change password
    EncryptedMasterSeeds,
    /// Username -> static kyber1024 public key
    ///
    /// Used to establish encryption key for orders and related data
    KyberPublicKeys,
    /// Public key | order ID -> multiple encrypted orders
    ///
    /// Enables multiple orders per public key receiver
    /// Only receiver can decrypt the orders
    Orders,
    /// Encryption key hash | encrypted listing ID -> ()
    ///
    /// Prevents platform from associating listings with a public key
    /// Encryption key is either per public key or per listing, depending on user's settings
    ///
    /// Lookup is done by prefix scan of `public key | hashed encryption key`, enabling fast lookup
    /// of all listings for a public key, or all listings of a public key with a specific encryption key
    EncryptedListingIds,
    /// Listing ID -> encrypted listing
    ///
    /// Enables encrypted listings to be stored in a way that prevents the platform from associating
    /// listings with a public key
    Listings,
    /// Note reference -> ()
    ///
    /// Stores which eCash notes have been spent. If a note's reference is stored here, it cannot be
    /// spent again.
    NoteRegistry,
    /// Attachment ID -> encrypted attachment
    /// Attachment is encrypted with the key of the listing it is attached to
    Attachments,
    /// Public key | encrypted key -> ()
    /// Used to store encrypted listing keys, so a user can look up their own listings
    EncryptedListingKeys,
    /// Deposit ID -> deposit amount
    Deposits,
    /// Ecash keys
    /// NoteValue -> RSA private key
    EcashKeys,
    /// Reference -> ()
    /// Stores references to eCash notes that have been spent to prevent double spending
    UsedEcashReferences,
    /// Public key | encrypted note -> ()
    /// Used to store encrypted SignedUnblindedNotes, so a user can look up their own notes
    EncryptedEcashNotes,
}

impl AsRef<[u8]> for TreeId {
    fn as_ref(&self) -> &[u8] {
        match self {
            TreeId::AuthTokens => b"auth_tokens",
            TreeId::EncryptedMasterSeeds => b"encrypted_master_seeds",
            TreeId::KyberPublicKeys => b"kyber_public_keys",
            TreeId::Orders => b"orders",
            TreeId::EncryptedListingIds => b"listing_ids",
            TreeId::Listings => b"listings",
            TreeId::NoteRegistry => b"note_registry",
            TreeId::Attachments => b"attachments",
            TreeId::EncryptedListingKeys => b"encrypted_listing_keys",
            TreeId::Deposits => b"deposits",
            TreeId::EcashKeys => b"ecash_keys",
            TreeId::UsedEcashReferences => b"used_ecash_references",
            TreeId::EncryptedEcashNotes => b"encrypted_ecash_notes",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Hash)]
enum Currency {
    Bitcoin, // Bitcoin, denominated in satoshis
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Hash)]
enum Condition {
    New,
    Refurbished,
    Used,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
struct Price(u64, Currency);

impl Price {
    fn to_string(&self) -> String {
        match self.1 {
            Currency::Bitcoin => format!("{} sats", self.0),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Listing {
    title: String,
    description: String,
    price: Price,
    quantity: u64,
    condition: Condition,
    attachments: Vec<AttachmentId>,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncryptedListing(#[serde_as(as = "Base64")] Vec<u8>);

impl Encrypt for Listing {
    type EncryptedType = EncryptedListing;

    fn encrypt(&self, key: &[u8; 32], rng: &mut CoreRng) -> Self::EncryptedType {
        let json = serde_json::to_vec(self).unwrap();
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from_slice(key));
        let nonce = Aes256Gcm::generate_nonce(rng);
        let mut encrypted_data = cipher.encrypt(&nonce, &json[..]).unwrap();
        encrypted_data.extend_from_slice(nonce.as_ref());
        EncryptedListing(encrypted_data)
    }
}

impl Decrypt for EncryptedListing {
    type DecryptedType = Listing;

    fn decrypt(&self, key: &[u8; 32]) -> Self::DecryptedType {
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from_slice(key));
        let (data, nonce) = self.0.split_at(self.0.len() - 12);
        let decrypted_data = cipher
            .decrypt(Nonce::<Aes256Gcm>::from_slice(&nonce), data)
            .unwrap();
        serde_json::from_slice(&decrypted_data).unwrap()
    }
}

trait RandomGen {
    fn gen(rng: &mut CoreRng) -> Self;
}

trait Encrypt {
    type EncryptedType;
    fn encrypt(&self, key: &[u8; 32], rng: &mut CoreRng) -> Self::EncryptedType;
}

trait Decrypt {
    type DecryptedType;
    fn decrypt(&self, key: &[u8; 32]) -> Self::DecryptedType;
}

macro_rules! impl_random_gen_for_array {
    ($type:ty, $len:expr) => {
        impl RandomGen for $type {
            fn gen(rng: &mut CoreRng) -> Self {
                let mut bytes = [0u8; $len];
                rng.fill_bytes(&mut bytes);
                Self(bytes)
            }
        }
    };
}

macro_rules! impl_encrypt_for_type {
    ($type:ty, $encrypted_type:ty) => {
        paste! {
            impl Encrypt for $type {
                type EncryptedType = $encrypted_type;

                fn encrypt(&self, key: &[u8; 32], rng: &mut CoreRng) -> Self::EncryptedType {
                    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from_slice(key));
                    let nonce = Aes256Gcm::generate_nonce(rng);
                    let mut encrypted_data = cipher.encrypt(&nonce, &self.0[..]).unwrap();
                    encrypted_data.extend_from_slice(nonce.as_ref());
                    [<$encrypted_type>](encrypted_data.try_into().unwrap())
                }
            }
        }
    };
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ListingId(#[serde_as(as = "Base64")] [u8; 32]);

// 32 bytes for the listing ID, 16 bytes tag, 12 bytes nonce
#[serde_as]
#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct EncryptedListingId(#[serde_as(as = "Base64")] [u8; 32 + 16 + 12]);
impl_random_gen_for_array!(ListingId, 32);
impl_encrypt_for_type!(ListingId, EncryptedListingId);

impl EncryptedListingId {
    fn decrypt(self, key: &[u8; 32]) -> ListingId {
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from_slice(key));
        let nonce_bytes = {
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes.copy_from_slice(&self.0[32 + 16..]);
            nonce_bytes
        };
        let nonce = Nonce::<Aes256Gcm>::from_slice(&nonce_bytes);
        let decrypted_data = cipher.decrypt(nonce, &self.0[..32 + 16]).unwrap();
        ListingId(decrypted_data.try_into().unwrap())
    }
}

#[repr(u16)]
#[derive(Serialize, Deserialize, Clone, Copy)]
enum AttachmentType {
    /// A WebP image
    WebP,
}

impl AttachmentType {
    fn from_mime(mime: &str) -> Option<Self> {
        match mime {
            "image/webp" => Some(Self::WebP),
            _ => None,
        }
    }

    fn to_mime(&self) -> &'static str {
        match self {
            Self::WebP => "image/webp",
        }
    }

    fn from_u16(val: u16) -> Option<Self> {
        match val {
            0 => Some(Self::WebP),
            _ => None,
        }
    }
}

// Attachment ID does not need to be encrypted as it's contained within the encrypted listing,
// and the attachment itself is encrypted using the listing's encryption key
#[serde_as]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AttachmentId(#[serde_as(as = "Base64")] [u8; 32]);
impl_random_gen_for_array!(AttachmentId, 32);
impl AsRef<[u8]> for AttachmentId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
struct Attachment(#[serde_as(as = "Base64")] Vec<u8>, AttachmentType);

impl Attachment {
    const MAX_SIZE_BYTES: usize = EncryptedAttachment::MAX_SIZE_BYTES - 16 - 12;

    fn encrypt_in_place(self, key: &[u8; 32], rng: &mut CoreRng) -> EncryptedAttachment {
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from_slice(key));
        let nonce = Aes256Gcm::generate_nonce(rng);
        let mut buf = self.0;
        // (attachment, type), tag, nonce
        // bracketed values are encrypted
        buf.reserve_exact(2 + 16 + 12);
        buf.extend_from_slice(&(self.1 as u16).to_le_bytes());
        cipher.encrypt_in_place(&nonce, &[], &mut buf).unwrap();
        buf.extend_from_slice(nonce.as_ref());
        EncryptedAttachment(buf)
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedAttachment(#[serde_as(as = "Base64")] Vec<u8>);

impl EncryptedAttachment {
    const MAX_SIZE_BYTES: usize = 10_000_000;

    fn decrypt_in_place(self, key: &[u8; 32]) -> Option<Attachment> {
        log!("decrypting attachment");
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from_slice(key));
        let mut buf = self.0;
        let nonce_bytes = {
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes.copy_from_slice(&buf[buf.len() - 12..]);
            nonce_bytes
        };
        let nonce = Nonce::<Aes256Gcm>::from_slice(&nonce_bytes);
        buf.truncate(buf.len() - 12);
        cipher.decrypt_in_place(nonce, &[], &mut buf).unwrap();
        let attachment_type = u16::from_le_bytes(buf[buf.len() - 2..].try_into().unwrap());
        buf.truncate(buf.len() - 2);
        Some(Attachment(buf, AttachmentType::from_u16(attachment_type)?))
    }
}

// ECASH STUFF

// deposits:
// user calls deposit(amount: u64) -> bolt11
// deposit creates a bolt11 with the amount and stores this in TreeId::DepositRequests
//   key = bolt11 payment hash
//   value = paid (bool), amount (u64)
// user pays bolt11
//   when bolt11 is paid, event is emitted in the server
//   the server marks the deposit as paid
// user calls claim_deposit(payment_hash, [unsigned notes]) -> (signed notes)
//   server checks that deposit is paid and that unsigned note amount == deposit amount
//   server signs the notes and returns them to the user
//
// withdrawals
// user calls withdraw(notes: u64, bolt11: String) -> success (bool)

pub struct DepositEntry {
    paid: bool,
    amount: u64,
}

impl DepositEntry {
    pub fn to_bytes(&self) -> [u8; 1 + 8] {
        let mut buf = [0u8; 1 + 8];
        buf[0] = self.paid as u8;
        buf[1..].copy_from_slice(&self.amount.to_le_bytes());
        buf
    }

    pub fn from_bytes(bytes: &[u8; 1 + 8]) -> Self {
        Self {
            paid: bytes[0] != 0,
            amount: u64::from_le_bytes(bytes[1..].try_into().unwrap()),
        }
    }
}

#[cfg(feature = "ssr")]
pub fn load_ecash_secret_keys() -> RegistrySecretKeys {
    let db = db::thread_local_db();
    let key_tree = db.open_tree(TreeId::EcashKeys).unwrap();
    let mut secret_keys = Vec::with_capacity(NOTE_VALUES.len());
    let mut note_values = NOTE_VALUES.clone();
    note_values.reverse();
    for note_value in note_values {
        let sk = RsaSecretKey::from_der(
            &key_tree
                .get(&(note_value as u64).to_le_bytes())
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        secret_keys.push(sk);
    }
    RegistrySecretKeys([
        secret_keys.pop().unwrap(),
        secret_keys.pop().unwrap(),
        secret_keys.pop().unwrap(),
        secret_keys.pop().unwrap(),
        secret_keys.pop().unwrap(),
        secret_keys.pop().unwrap(),
        secret_keys.pop().unwrap(),
        secret_keys.pop().unwrap(),
        secret_keys.pop().unwrap(),
    ])
}

pub fn load_ecash_public_keys(sks: RegistrySecretKeys) -> RegistryPublicKeys {
    RegistryPublicKeys(sks.0.map(|sk| sk.clone().public_key().unwrap()))
}

#[server(GetRegistryPublicKeys)]
async fn get_registry_public_keys() -> Result<HashMap<NoteValue, Vec<u8>>, ServerFnError> {
    let pks = load_ecash_public_keys(load_ecash_secret_keys());
    let mut hm = HashMap::new();
    for value in NOTE_VALUES.iter() {
        hm.insert(*value, pks.0[value.get_index()].to_der().unwrap());
    }
    Ok(hm)
}

#[server(Deposit)]
async fn deposit(amount: u64) -> Result<String, ServerFnError> {
    let bolt11 = NODE
        .bolt11_payment()
        .receive(amount * 1000, "", 3600)
        .unwrap();
    let deposit = DepositEntry {
        paid: false,
        amount,
    };
    let db = db::thread_local_db().open_tree(TreeId::Deposits).unwrap();
    db.insert(bolt11.payment_hash().as_byte_array(), &deposit.to_bytes())
        .unwrap();
    Ok(bolt11.to_string())
}

#[server(ClaimDeposit)]
async fn claim_deposit(
    payment_hash: String,
    blinded_notes: Vec<BlindedNote>,
) -> Result<Vec<String>, ServerFnError> {
    let db = db::thread_local_db().open_tree(TreeId::Deposits).unwrap();
    let key = sha256::Hash::from_str(&payment_hash).unwrap();
    let value = db.get(key.as_byte_array()).unwrap().unwrap();
    let deposit_entry = DepositEntry::from_bytes(array_ref![value, 0, 9]);
    if !deposit_entry.paid {
        return Err(ServerFnError::new("deposit not paid"));
    }

    let mut signatures = Vec::with_capacity(blinded_notes.len());
    let registry_secret_keys = load_ecash_secret_keys();
    for note in blinded_notes {
        let signature = note.sign(&registry_secret_keys).unwrap();
        signatures.push(bts(&signature.0));
    }
    // prevent double claiming
    db.remove(key.as_byte_array()).unwrap();

    Ok(signatures)
}

#[server(TransferNotes)]
async fn transfer_notes(tx: TransferTransaction) -> Result<Vec<String>, ServerFnError> {
    let sks = load_ecash_secret_keys();
    let registry_public_keys = load_ecash_public_keys(sks.clone());
    let tree = db::thread_local_db()
        .open_tree(TreeId::UsedEcashReferences)
        .unwrap();
    if !tx.validate(&registry_public_keys, |reference| {
        !tree.contains_key(reference).unwrap()
    }) {
        return Err(ServerFnError::new("invalid transaction"));
    }
    for note in tx.source_notes.iter() {
        tree.insert(&note.reference.0, &[]).unwrap();
    }

    let mut sigs = Vec::with_capacity(tx.target_notes.len());
    for note in tx.target_notes.iter() {
        let sig = note.sign(&sks).unwrap();
        sigs.push(bts(&sig.0));
    }

    Ok(sigs)
}

#[server(UploadEncryptedEcashNotes)]
async fn upload_encrypted_ecash_notes(
    pk: KyberPublicKey,
    notes: Vec<EncryptedSignedUnblindedNote>,
) -> Result<(), ServerFnError> {
    let tree = db::thread_local_db()
        .open_tree(TreeId::EncryptedEcashNotes)
        .unwrap();
    for note in notes {
        let mut key = Vec::new();
        key.extend_from_slice(&pk.0);
        key.extend_from_slice(&note.0);
        tree.insert(&key, &[]).unwrap();
    }
    Ok(())
}

#[server(DownloadEncryptedEcashNotes)]
async fn download_encrypted_ecash_notes(
    pk: KyberPublicKey,
) -> Result<Vec<EncryptedSignedUnblindedNote>, ServerFnError> {
    let tree = db::thread_local_db()
        .open_tree(TreeId::EncryptedEcashNotes)
        .unwrap();
    Ok(tree
        .scan_prefix(&pk.0)
        .map(|key| {
            let (k, _) = key.unwrap();
            let mut note = EncryptedSignedUnblindedNote(Vec::new());
            note.0.extend_from_slice(&k[pk.0.len()..]);
            note
        })
        .collect())
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSignedUnblindedNote(#[serde_as(as = "Base64")] Vec<u8>);

impl Decrypt for EncryptedSignedUnblindedNote {
    type DecryptedType = SignedUnblindedNote;

    fn decrypt(&self, key: &[u8; 32]) -> Self::DecryptedType {
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from_slice(key));
        let (data, nonce) = self.0.split_at(self.0.len() - 12);
        let decrypted_data = cipher
            .decrypt(Nonce::<Aes256Gcm>::from_slice(&nonce), data)
            .unwrap();
        serde_json::from_slice(&decrypted_data).unwrap()
    }
}

enum TransactionType {
    /// This transaction is depositing funds into the user's account
    Deposit,
    /// This transaction is withdrawing funds from the user's account
    /// to a BOLT11 address
    Withdrawal,
    /// This transaction is transferring funds via claiming the funds
    Transfer,
}

/// The only possible note amounts in satoshis
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
#[repr(u32)]
pub enum NoteValue {
    One = 1,
    Ten = 10,
    OneHundred = 100,
    OneThousand = 1_000,
    TenThousand = 10_000,
    OneHundredThousand = 100_000,
    OneMillion = 1_000_000,
    TenMillion = 10_000_000,
    OneHundredMillion = 100_000_000,
}

impl NoteValue {
    fn from_u32(num: u32) -> Option<Self> {
        match num {
            1 => Some(NoteValue::One),
            10 => Some(NoteValue::Ten),
            100 => Some(NoteValue::OneHundred),
            1_000 => Some(NoteValue::OneThousand),
            10_000 => Some(NoteValue::TenThousand),
            100_000 => Some(NoteValue::OneHundredThousand),
            1_000_000 => Some(NoteValue::OneMillion),
            10_000_000 => Some(NoteValue::TenMillion),
            100_000_000 => Some(NoteValue::OneHundredMillion),
            _ => None,
        }
    }

    fn get_index(&self) -> usize {
        match self {
            NoteValue::One => 0,
            NoteValue::Ten => 1,
            NoteValue::OneHundred => 2,
            NoteValue::OneThousand => 3,
            NoteValue::TenThousand => 4,
            NoteValue::OneHundredThousand => 5,
            NoteValue::OneMillion => 6,
            NoteValue::TenMillion => 7,
            NoteValue::OneHundredMillion => 8,
        }
    }
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
struct NoteReference(#[serde_as(as = "Base64")] [u8; 32]);
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
struct BlindedNoteReference(#[serde_as(as = "Base64")] Vec<u8>);

/// A note as initially generated by the user. Not signed and not valid.
#[derive(Debug, Clone)]
struct UnsignedNote {
    value: NoteValue,
    reference: NoteReference,
}

impl UnsignedNote {
    /// Generate a new note with a random reference
    fn gen<R: RngCore + CryptoRng>(value: NoteValue, rng: &mut R) -> Self {
        let mut reference = [0u8; 32];
        rng.fill_bytes(&mut reference);
        UnsignedNote {
            value,
            reference: NoteReference(reference),
        }
    }

    fn new(value: NoteValue, reference: NoteReference) -> Self {
        UnsignedNote { value, reference }
    }

    /// Blind the note using the given registry keys
    fn blind<R: RngCore + CryptoRng>(
        &self,
        registry_public_keys: &RegistryPublicKeys,
        rng: &mut R,
    ) -> Option<(BlindedNote, BlindingSecret)> {
        let res = registry_public_keys
            .get_key_for(self.value)
            .blind(rng, &self.reference.0, false, &BlindingOptions::default())
            .ok()?;

        Some((
            BlindedNote {
                value: self.value,
                blinded_reference: BlindedNoteReference(res.blind_msg.0.clone()),
            },
            res.secret,
        ))
    }
}

/// A note that has been blinded and is ready to be signed by the registry
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlindedNote {
    value: NoteValue,
    blinded_reference: BlindedNoteReference,
}

impl BlindedNote {
    #[cfg(feature = "ssr")]
    /// [SERVER] signs the note to prove that it is valid and returns signature
    fn sign(&self, registry_secret_keys: &RegistrySecretKeys) -> Option<BlindSignature> {
        let sk = registry_secret_keys.get_key_for(self.value);
        Some(
            sk.blind_sign(
                &mut CoreRng::default(),
                self.blinded_reference.0.clone(),
                &BlindingOptions::default(),
            )
            .ok()?,
        )
    }

    // #[cfg(not(feature = "ssr"))]
    /// [CLIENT] unblinds the note and returns the unblinded note
    fn add_server_signature(
        self,
        signature: BlindSignature,
        registry_public_keys: &RegistryPublicKeys,
        original_reference: NoteReference,
        blinding_secret: BlindingSecret,
    ) -> Option<SignedUnblindedNote> {
        let sig = registry_public_keys
            .get_key_for(self.value)
            .finalize(
                &signature,
                &blinding_secret,
                None,
                original_reference.0,
                &BlindingOptions::default(),
            )
            .ok()?;

        Some(SignedUnblindedNote {
            value: self.value,
            reference: original_reference,
            signature: UnblindedSignature(sig.0.try_into().expect("sig should be 512 bytes")),
        })
    }
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UnblindedSignature(#[serde_as(as = "Base64")] [u8; 512]);

/// A note that has been signed by the registry and unblinded by the client
/// Valid and spendable with the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedUnblindedNote {
    /// The value of the note
    value: NoteValue,
    /// The unblinded reference number of the note
    reference: NoteReference,
    /// The unblinded signature of the note
    /// Verified against RegistryPublicKeys.get_key_for(value)
    signature: UnblindedSignature,
}

impl Encrypt for SignedUnblindedNote {
    type EncryptedType = EncryptedSignedUnblindedNote;

    fn encrypt(&self, key: &[u8; 32], rng: &mut CoreRng) -> Self::EncryptedType {
        let json = serde_json::to_vec(self).unwrap();
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from_slice(key));
        let nonce = Aes256Gcm::generate_nonce(rng);
        let mut encrypted_data = cipher.encrypt(&nonce, &json[..]).unwrap();
        encrypted_data.extend_from_slice(nonce.as_ref());
        EncryptedSignedUnblindedNote(encrypted_data)
    }
}

impl SignedUnblindedNote {
    /// [SERVER/CLIENT] verifies the note is valid and the reference is valid
    fn verify(
        &self,
        registry_public_keys: &RegistryPublicKeys,
        reference_valid: impl Fn([u8; 32]) -> bool,
    ) -> bool {
        let pk = registry_public_keys.get_key_for(self.value);
        let signature = RsaSignature::new(Vec::from(&self.signature.0[..]));
        signature
            .verify(pk, None, &self.reference.0, &BlindingOptions::default())
            .is_ok()
            && reference_valid(self.reference.0)
    }

    fn to_bytes(&self) -> [u8; 32 / 8 + 32 + 512] {
        let mut bytes = [0u8; 32 / 8 + 32 + 512];
        bytes[0..4].copy_from_slice(&(self.value as u32).to_le_bytes());
        bytes[4..36].copy_from_slice(&self.reference.0);
        bytes[36..36 + 512].copy_from_slice(&self.signature.0);
        bytes
    }

    fn from_bytes(
        bytes: &[u8; 32 / 8 + 32 + 512],
        registry_public_keys: &RegistryPublicKeys,
    ) -> Option<Self> {
        let value = u32::from_le_bytes(*array_ref!(bytes, 0, 4));
        let reference = *array_ref!(bytes, 4, 32);
        let signature = *array_ref!(bytes, 36, 512);
        let note = SignedUnblindedNote {
            value: NoteValue::from_u32(value)?,
            reference: NoteReference(reference),
            signature: UnblindedSignature(signature),
        };
        if note.verify(registry_public_keys, |_| true) {
            Some(note)
        } else {
            None
        }
    }
}

/// A spend plan is a way to spend a set of notes to make up a certain amount
enum SpendPlan {
    /// The amount is the sum of the values of the notes
    UseAllNotes,
    /// The amount can be made up entirely of already existing notes
    UseCurrentNotes(Vec<SignedUnblindedNote>),
    /// The amount cannot be made up purely of already existing notes. We must break down a larger note to make up the difference
    /// Returns notes that can be used already, as well a TransferTransaction that breaks down notes to make some new notes
    /// that are then used to make up the amount
    BreakDownNotes {
        /// Use these notes that already exist
        use_current_notes: Vec<SignedUnblindedNote>,
        /// We need to break this note down to make up the amount
        note_to_break_down: SignedUnblindedNote,
        /// Make this set of notes to fill the amount
        make_and_use_these_other_notes: Vec<NoteValue>,
        /// We'll have leftover from note_to_break_down, which consists of these notes
        make_leftover_notes: Vec<NoteValue>,
    },
    /// We don't have enough notes to make up the amount
    NoPossibleSpend,
}

pub const NOTE_VALUES: [NoteValue; 9] = [
    NoteValue::OneHundredMillion,
    NoteValue::TenMillion,
    NoteValue::OneMillion,
    NoteValue::OneHundredThousand,
    NoteValue::TenThousand,
    NoteValue::OneThousand,
    NoteValue::OneHundred,
    NoteValue::Ten,
    NoteValue::One,
];

fn break_down_amount_into_notes(mut value: u64) -> Vec<NoteValue> {
    let mut notes = vec![];
    while value > 0 {
        let note_value = NOTE_VALUES
            .iter()
            .find(|&&val| value >= val as u64)
            .unwrap_or(&NoteValue::One); // default to One if none match

        notes.push(*note_value);
        value -= *note_value as u64;
    }
    notes
}

/// Given a set of notes, choose a subset of them to be spent in a transaction.
/// If we can't produce the exact amount, we break down existing notes to make up the amount.
/// If SpendPlan::UseCurrentNotes or SpendPlan::BreakDownNotes is returned, this function will remove spent notes from the input
/// and use them in the output
fn choose_notes_for_payment(notes: &mut Vec<SignedUnblindedNote>, amount: u64) -> SpendPlan {
    let sum = notes.iter().map(|note| note.value as u64).sum::<u64>();
    if sum == amount {
        return SpendPlan::UseAllNotes;
    }
    if sum < amount {
        return SpendPlan::NoPossibleSpend;
    }
    // sort notes by value, smallest last - we'll use those first
    notes.sort_by(|a, b| b.value.cmp(&a.value));
    let mut remaining = amount;
    let mut use_current_notes = Vec::new();
    while remaining > 0 {
        let note = notes.pop().unwrap();
        let value = note.value as u64;
        if value > remaining {
            let note_to_break_down = note;
            let left_over = value - remaining;
            // build the remaining amount that we'll use to fill out the payment
            let make_and_use_these_other_notes = break_down_amount_into_notes(remaining);
            // build the left over amount
            let make_leftover_notes = break_down_amount_into_notes(left_over);

            return SpendPlan::BreakDownNotes {
                use_current_notes,
                note_to_break_down,
                make_and_use_these_other_notes,
                make_leftover_notes,
            };
        }
        remaining -= value;
        use_current_notes.push(note);
    }

    SpendPlan::UseCurrentNotes(use_current_notes)
}

/// A transaction that transfers funds from a set of source notes to a set of target notes
/// Enables transfers of ownership within the platform, and allows notes to be broken down or combined
/// to form larger or smaller notes.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TransferTransaction {
    source_notes: Vec<SignedUnblindedNote>,
    target_notes: Vec<BlindedNote>,
}

#[cfg(feature = "ssr")]
impl TransferTransaction {
    /// [SERVER/CLIENT] Verifies all signatures and the total value of the source notes equals the total value of the target notes
    fn validate(
        &self,
        registry_public_keys: &RegistryPublicKeys,
        reference_valid: impl Fn([u8; 32]) -> bool,
    ) -> bool {
        let reference_valid = |reference| reference_valid(reference);
        let sigs_match = self
            .source_notes
            .iter()
            .all(|note| note.verify(registry_public_keys, reference_valid));
        let total_values_match = self
            .source_notes
            .iter()
            .map(|note| note.value as u32)
            .sum::<u32>()
            == self
                .target_notes
                .iter()
                .map(|note| note.value as u32)
                .sum::<u32>();
        sigs_match && total_values_match
    }

    /// [SERVER] Signs the target notes with the secret keys and returns the signatures, in order
    /// of that of the target notes. These should be sent to the client to unblind the notes
    fn sign_target_notes(&self, registry_secret_keys: &RegistrySecretKeys) -> Vec<BlindSignature> {
        self.target_notes
            .iter()
            .map(|note| {
                note.sign(registry_secret_keys)
                    .expect("signing should work")
            })
            .collect()
    }
}

macro_rules! registry_keys {
    ($name:ident, $key_type:ty) => {
        #[derive(Debug, Clone)]
        pub struct $name([$key_type; 9]);

        impl $name {
            fn get_key_for(&self, value: NoteValue) -> &$key_type {
                &self.0[value.get_index()]
            }
        }
    };
}

registry_keys!(RegistryPublicKeys, RsaPublicKey);
registry_keys!(RegistrySecretKeys, RsaSecretKey);

/// A transaction that claims funds from a note and sends them to a BOLT11 invoice
#[cfg(feature = "ssr")]
struct WithdrawalTransaction {
    /// The BOLT11 invoice that the user wants the mint to pay
    invoice: Bolt11Invoice,
    /// The unblinded reference number of the note being claimed
    source_note_reference: [u8; 32],
    /// The unblinded signature of the note being claimed
    source_note_signature: [u8; 512],
}

#[cfg(test)]
mod tests {
    use std::array;

    use blind_rsa_signatures::KeyPair as RsaKeyPair;

    use super::*;

    fn test_registry() {
        let mut rng = CoreRng::default();
        let registry_keys: [RsaKeyPair; 9] =
            array::from_fn(|_| RsaKeyPair::generate(&mut rng, 4096).unwrap());
        let registry_public_keys = RegistryPublicKeys(registry_keys.clone().map(|kp| kp.pk));
        let registry_secret_keys = RegistrySecretKeys(registry_keys.map(|kp| kp.sk));

        let notes: [UnsignedNote; 100] =
            array::from_fn(|_| UnsignedNote::gen(NoteValue::OneHundred, &mut rng));

        let blinded_notes = notes
            .iter()
            .map(|note| note.blind(&registry_public_keys, &mut rng).unwrap())
            .collect::<Vec<_>>();

        let secrets = blinded_notes
            .clone()
            .into_iter()
            .map(|note| note.1)
            .collect::<Vec<_>>();
        let blinded_notes = blinded_notes
            .clone()
            .into_iter()
            .map(|note| note.0)
            .collect::<Vec<_>>();

        let signed_notes = blinded_notes
            .iter()
            .map(|note| note.sign(&registry_secret_keys).unwrap())
            .collect::<Vec<_>>();
        let signed_unblinded_notes = blinded_notes
            .clone()
            .into_iter()
            .enumerate()
            .map(|(i, note)| {
                note.add_server_signature(
                    signed_notes[i].clone(),
                    &registry_public_keys,
                    notes[i].reference.clone(),
                    secrets[i].clone(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        assert!(signed_unblinded_notes
            .iter()
            .all(|note| note.verify(&registry_public_keys, |_| true)));

        let transfer = TransferTransaction {
            source_notes: signed_unblinded_notes,
            target_notes: blinded_notes,
        };

        assert!(transfer.validate(&registry_public_keys, |_| true));
    }
}
