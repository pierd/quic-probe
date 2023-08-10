use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use thiserror::Error;

#[cfg(feature = "tls-native-roots")]
fn add_native_roots(roots: &mut rustls::RootCertStore) {
    tracing::debug!("Loading native root certificates");
    match rustls_native_certs::load_native_certs() {
        Ok(certs) => {
            for cert in certs {
                let cert = rustls::Certificate(cert.0);
                if let Err(e) = roots.add(&cert) {
                    tracing::warn!(?cert, "Failed to parse trust anchor: {}", e);
                }
            }
        }

        Err(e) => {
            tracing::warn!("Failed load any default trust roots: {}", e);
        }
    };
}

#[cfg(feature = "tls-webpki-roots")]
fn add_webpki_roots(roots: &mut rustls::RootCertStore) {
    tracing::debug!("Loading webpki root certificates");
    roots.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
}

fn load_root_certs() -> rustls::RootCertStore {
    #[cfg(any(feature = "tls-native-roots", feature = "tls-webpki-roots"))]
    {
        let mut roots = rustls::RootCertStore::empty();
        #[cfg(feature = "tls-native-roots")]
        add_native_roots(&mut roots);
        #[cfg(feature = "tls-webpki-roots")]
        add_webpki_roots(&mut roots);
        roots
    }
    #[cfg(not(any(feature = "tls-native-roots", feature = "tls-webpki-roots")))]
    {
        tracing::debug!("Creating empty root certificates store");
        rustls::RootCertStore::empty()
    }
}

pub struct ProbeBuilder {
    pub tls_config: rustls::ClientConfig,
    transport_config: quinn::TransportConfig,
    bind_addr: SocketAddr,
}

impl ProbeBuilder {
    pub fn initial_rtt(mut self, rtt: Duration) -> Self {
        self.transport_config.initial_rtt(rtt);
        self
    }

    pub fn max_idle_timeout<T: TryInto<quinn::IdleTimeout>>(
        mut self,
        timeout: T,
    ) -> Result<Self, T::Error> {
        self.transport_config
            .max_idle_timeout(Some(timeout.try_into()?));
        Ok(self)
    }

    pub fn bind_addr(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = addr;
        self
    }

    pub fn build(self) -> Result<Probe, std::io::Error> {
        let mut endpoint = quinn::Endpoint::client(self.bind_addr)?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(self.tls_config));
        client_config.transport_config(Arc::new(self.transport_config));
        endpoint.set_default_client_config(client_config);
        Ok(Probe { endpoint })
    }
}

impl Default for ProbeBuilder {
    fn default() -> Self {
        let roots = load_root_certs();
        let tls_config = rustls::ClientConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();

        Self {
            tls_config,
            transport_config: quinn::TransportConfig::default(),
            bind_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        }
    }
}

#[derive(Clone)]
pub struct Probe {
    endpoint: quinn::Endpoint,
}

#[derive(Clone, Debug, Error)]
pub enum ProbeError {
    #[error("Invalid DNS name: {0}")]
    InvalidDnsName(String),
    #[error("Invalid remote address: {0}")]
    InvalidRemoteAddress(SocketAddr),
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl From<quinn::ConnectError> for ProbeError {
    fn from(e: quinn::ConnectError) -> Self {
        match e {
            quinn::ConnectError::InvalidDnsName(name) => ProbeError::InvalidDnsName(name),
            quinn::ConnectError::InvalidRemoteAddress(addr) => {
                ProbeError::InvalidRemoteAddress(addr)
            }
            _ => ProbeError::InternalError(format!("{}", e)),
        }
    }
}

impl Probe {
    pub async fn probe(&self, addr: SocketAddr, server_name: &str) -> Result<bool, ProbeError> {
        let connect_result = self.endpoint.connect(addr, server_name);
        tracing::debug!(?connect_result, "Connecting to {}({})", server_name, addr);
        let connect_result = connect_result?.await;
        tracing::debug!(?connect_result, "Connection result");
        Ok(!matches!(
            connect_result,
            Err(quinn::ConnectionError::TimedOut)
        ))
    }
}
