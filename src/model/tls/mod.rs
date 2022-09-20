#[cfg(not(feature = "fips"))]
#[path = "default.rs"]
mod imp;
#[cfg(feature = "fips")]
#[path = "fips.rs"]
mod imp;

use model::error::RdpResult;
use std::fmt;
use std::io::{self, Read, Write};

#[derive(Clone)]
pub struct Certificate(imp::Certificate);

impl Certificate {
    // Parses a DER-formatted X509 certificate.
    pub fn from_der(der: &[u8]) -> RdpResult<Certificate> {
        let cert = imp::Certificate::from_der(der)?;
        Ok(Certificate(cert))
    }

    /// Returns the DER-encoded representation of this certificate.
    pub fn to_der(&self) -> RdpResult<Vec<u8>> {
        let der = self.0.to_der()?;
        Ok(der)
    }
}

pub struct TlsStream<S>(imp::TlsStream<S>);

impl<S: fmt::Debug> fmt::Debug for TlsStream<S> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl<S: Read + Write> TlsStream<S> {
    pub fn new(check_certificate: bool, sock: S) -> RdpResult<Self> {
        Ok(Self(imp::TlsStream::new(check_certificate, sock)?))
    }

    /// Returns a shared reference to the inner stream.
    pub fn get_ref(&self) -> &S {
        self.0.get_ref()
    }

    /// Returns a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut S {
        self.0.get_mut()
    }

    /// Returns the peer's leaf certificate, if available.
    pub fn peer_certificate(&self) -> RdpResult<Option<Certificate>> {
        Ok(self.0.peer_certificate()?.map(Certificate))
    }

    /// Shuts down the TLS session.
    pub fn shutdown(&mut self) -> io::Result<()> {
        self.0.shutdown()?;
        Ok(())
    }
}

impl<S: Read + Write> Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<S: Read + Write> Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
