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

use std::sync::{Arc, LazyLock};

use rustls::ClientConfig;
use rustls::RootCertStore;

/// Built-once, shared-many `rustls::ClientConfig` whose root store is the
/// bundled Mozilla CA list. Memoized via `LazyLock` so the (non-trivial)
/// `RootCertStore` construction runs exactly once per process even when
/// many reqwest builders ask for the config.
///
/// `LazyLock` over `OnceLock`/`once_cell` because we already use `LazyLock`
/// elsewhere in the crate (`config::CONFIG_PATHS_CACHE`) and it's in the
/// standard library — no extra dep.
static DEFAULT_TLS_CONFIG: LazyLock<Arc<ClientConfig>> = LazyLock::new(|| {
    let mut roots = RootCertStore::empty();
    // webpki-roots ships a `&'static [TrustAnchor<'static>]`; cloning each
    // entry is cheap and the resulting `RootCertStore` owns its data.
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(config)
});

/// Returns the shared `rustls::ClientConfig` (see `DEFAULT_TLS_CONFIG`).
/// The returned `Arc` is cheap to clone — the underlying config and root
/// store are constructed exactly once.
pub fn default_tls_config() -> Arc<ClientConfig> {
    Arc::clone(&DEFAULT_TLS_CONFIG)
}
