use rustls::{
    client::{NoClientSessionStorage, ServerCertVerified, ServerCertVerifier},
    ClientConfig, ClientConnection, RootCertStore, ServerName, Stream,
};
use std::convert::TryInto;
use std::fmt;
use std::io::{self, Read, Write};
use std::sync::Arc;
use std::time::SystemTime;

use model::error::{Error, RdpError, RdpErrorKind, RdpResult};

/// Marks all server certificates as valid
/// so it can be used to turn off the server certificate
/// validation on the client-side.
struct DummyTlsVerifier;

impl ServerCertVerifier for DummyTlsVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

#[derive(Clone)]
pub struct Certificate(rustls::Certificate);

impl Certificate {
    pub fn from_der(der: &[u8]) -> RdpResult<Self> {
        Ok(Self(rustls::Certificate(der.to_vec())))
    }

    pub fn to_der(&self) -> RdpResult<Vec<u8>> {
        Ok(self.0 .0.clone())
    }
}

/// Copied from rustls library with removed trait bounds (Read + Write)
/// By removing trait bounds we don't have to update
/// other structs that depends on the Stream enum
pub struct TlsStream<T: Sized> {
    /// Our connection
    pub conn: ClientConnection,

    /// The underlying transport, like a socket
    pub sock: T,
}

impl<T> TlsStream<T>
where
    T: Read + Write,
{
    /// Get a reference to the underlying socket
    pub fn get_ref(&self) -> &T {
        &self.sock
    }

    /// Get a mutable reference to the underlying socket
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.sock
    }

    fn as_stream(&mut self) -> Stream<ClientConnection, T> {
        Stream {
            conn: &mut self.conn,
            sock: &mut self.sock,
        }
    }
}

impl<T> Read for TlsStream<T>
where
    T: Read + Write,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.as_stream().read(buf)
    }
}

impl<T> Write for TlsStream<T>
where
    T: Read + Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.as_stream().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.as_stream().flush()
    }
}

impl<S: fmt::Debug> fmt::Debug for TlsStream<S> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self, fmt)
    }
}

impl<T> TlsStream<T>
where
    T: Read + Write,
{
    pub fn new(check_certificate: bool, sock: T) -> RdpResult<Self> {
        let root_store = RootCertStore::empty();
        let mut config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        if !check_certificate {
            let mut config = config.dangerous();
            let verifier = Arc::new(DummyTlsVerifier {});
            config.set_certificate_verifier(verifier)
        }

        config.enable_sni = false;
        // We do not use the Server Name Indication (SNI) extension
        // during the client handshake, but the rustls library requires
        // a valid DNS domain name for the server regardless of that
        // setting, so we need to provide a valid name.
        // We can't use an empty string here.
        let server_name: ServerName = "servername".try_into().unwrap();
        config.session_storage = Arc::new(NoClientSessionStorage {});

        let arc = Arc::new(config);
        let conn = ClientConnection::new(arc, server_name).map_err(|_| Error::SslError)?;

        Ok(Self { conn, sock })
    }

    pub fn peer_certificate(&self) -> RdpResult<Option<Certificate>> {
        if let Some(certs) = self.conn.peer_certificates() {
            if let Some(cert) = certs.first() {
                Ok(Some(Certificate(cert.clone())))
            } else {
                Err(Error::RdpError(RdpError::new(
                    RdpErrorKind::InvalidData,
                    "certificates chain is empty",
                )))
            }
        } else {
            Err(Error::RdpError(RdpError::new(
                RdpErrorKind::InvalidData,
                "certificates chain is unavialable",
            )))
        }
    }

    pub fn shutdown(&mut self) -> io::Result<()> {
        self.conn.send_close_notify();
        self.flush()?;
        Ok(())
    }
}
