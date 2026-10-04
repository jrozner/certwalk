use std::time::Duration;

use anyhow::Result;

use crate::DiscoveredDomain;

/// A source of domain identities and certificate history.
///
/// Implementations return unique, normalized identities within the requested
/// domain and its subdomains, sorted by domain name. Wildcard identities remain
/// separate from concrete hosts. Issuance dates use the earliest/latest observed
/// certificate validity starts, normalized to UTC.
///
/// Network failures or malformed source data must be reported as errors rather
/// than empty results. Backends should honor the supplied request timeout.
///
/// This trait supports trait objects, allowing callers to supply a backend
/// without depending on its concrete type.
pub trait CertificateTransparencyBackend {
    fn discover(&self, domain: &str, timeout: Duration) -> Result<Vec<DiscoveredDomain>>;
}
