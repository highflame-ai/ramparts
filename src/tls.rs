//! Shared TLS configuration for every reqwest client ramparts builds.
//!
//! Why this exists: reqwest 0.13's default `rustls` feature pulls in
//! `rustls-platform-verifier`, which loads CAs from the host OS trust store.
//! That fails outright on some user environments (we've seen "No CA
//! certificates were loaded from the system" on otherwise-working macOS
//! installs), which surfaces as the very opaque
//! `reqwest::Client::builder().build() -> "builder error"`.
//!
//! Switching to a built-in Mozilla CA bundle (`webpki-roots`) makes HTTPS
//! connectivity reproducible across environments and removes our dependency
//! on the host trust store. Every `reqwest::Client` we build for outbound
//! traffic should use `default_tls_config()` via
//! `Client::builder().use_preconfigured_tls(...)` so this propagates to the
//! simple HTTP path, the rmcp streamable HTTP path, and the scanner's own
//! reqwest client.

use std::sync::Arc;

use rustls::ClientConfig;
use rustls::RootCertStore;

/// Build a fresh `rustls::ClientConfig` whose root store is the bundled
/// Mozilla CA list. The returned `ClientConfig` is `Arc`-wrapped so multiple
/// reqwest builders can share it without recomputing the root store.
pub fn default_tls_config() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    // webpki-roots ships a `&'static [TrustAnchor<'static>]`; cloning each
    // entry is cheap and the resulting `RootCertStore` owns its data.
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(config)
}
