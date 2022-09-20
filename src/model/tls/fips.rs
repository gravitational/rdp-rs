extern crate boring;

use self::boring::ssl::{self, SslConnector, SslMethod, SslStream, SslVerifyMode};
use self::boring::x509::X509;
use self::boring::fips;
use model::error::{Error, RdpResult};
use std::fmt;
use std::io::{self, Read, Write};

#[derive(Clone)]
pub struct Certificate(X509);

impl Certificate {
    pub fn from_der(der: &[u8]) -> RdpResult<Self> {
        Ok(Certificate(
            X509::from_der(der).map_err(|e| Error::FromError(e.to_string()))?,
        ))
    }

    pub fn to_der(&self) -> RdpResult<Vec<u8>> {
        Ok(self
            .0
            .to_der()
            .map_err(|e| Error::FromError(e.to_string()))?)
    }
}

pub struct TlsStream<S>(SslStream<S>);

impl<S: fmt::Debug> fmt::Debug for TlsStream<S> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl<S: Read + Write> TlsStream<S> {
    pub fn new(check_certificate: bool, stream: S) -> RdpResult<Self> {
        if !fips::enabled() {
            panic!("FIPS mode not enabled")
        }

        let mut connector = SslConnector::builder(SslMethod::tls())
            .map_err(|_| Error::SslError)?
            .build()
            .configure()
            .map_err(|_| Error::SslError)?
            .verify_hostname(false)
            .use_server_name_indication(false);

        if !check_certificate {
            connector.set_verify(SslVerifyMode::NONE);
        }

        let stream = match connector.connect("", stream) {
            Ok(stream) => stream,
            Err(_) => return Err(Error::SslError),
        };

        Ok(Self(stream))
    }

    pub fn get_ref(&self) -> &S {
        self.0.get_ref()
    }

    pub fn get_mut(&mut self) -> &mut S {
        self.0.get_mut()
    }

    pub fn peer_certificate(&self) -> RdpResult<Option<Certificate>> {
        Ok(self.0.ssl().peer_certificate().map(Certificate))
    }

    pub fn shutdown(&mut self) -> io::Result<()> {
        match self.0.shutdown() {
            Ok(_) => Ok(()),
            Err(ref e) if e.code() == ssl::ErrorCode::ZERO_RETURN => Ok(()),
            Err(e) => Err(e
                .into_io_error()
                .unwrap_or_else(|e| io::Error::new(io::ErrorKind::Other, e))),
        }
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
