extern crate rustls;

use model::data::Message;
use model::error::{Error, RdpError, RdpErrorKind, RdpResult};
use std::convert::TryInto;
use std::io::{Cursor, Read, Write};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::SystemTime;

use self::rustls::{
    client::{NoClientSessionStorage, ServerCertVerified, ServerCertVerifier},
    Certificate, ClientConfig, ClientConnection, ConnectionCommon, Error as RustlsError,
    RootCertStore, ServerName, SideData, Stream as RustlsStream,
};

/// Marks all server certificates as valid
/// so it can be used to turn off the server certificate
/// validation on the client-side.
struct DummyTlsVerifier;

impl ServerCertVerifier for DummyTlsVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }
}

/// Copied from rustls library with removed trait bounds (Read + Write)
/// By removing trait bounds we don't have to update
/// other structs that depends on the Stream enum
pub struct StreamOwned<C: Sized, T: Sized> {
    /// Our conneciton
    pub conn: C,

    /// The underlying transport, like a socket
    pub sock: T,
}

impl<C, T, S> StreamOwned<C, T>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    T: Read + Write,
    S: SideData,
{
    /// Make a new StreamOwned taking the Connection `conn` and socket-like
    /// object `sock`.  This does not fail and does no IO.
    ///
    /// This is the same as `Stream::new` except `conn` and `sock` are
    /// moved into the StreamOwned.
    pub fn new(conn: C, sock: T) -> Self {
        Self { conn, sock }
    }

    /// Get a reference to the underlying socket
    pub fn get_ref(&self) -> &T {
        &self.sock
    }

    /// Get a mutable reference to the underlying socket
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.sock
    }

    fn as_stream(&mut self) -> RustlsStream<C, T> {
        RustlsStream {
            conn: &mut self.conn,
            sock: &mut self.sock,
        }
    }
}

impl<C, T, S> Read for StreamOwned<C, T>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    T: Read + Write,
    S: SideData,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.as_stream().read(buf)
    }

    #[cfg(read_buf)]
    fn read_buf(&mut self, buf: &mut std::io::ReadBuf<'_>) -> std::io::Result<()> {
        self.as_stream().read_buf(buf)
    }
}

impl<C, T, S> Write for StreamOwned<C, T>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    T: Read + Write,
    S: SideData,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.as_stream().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.as_stream().flush()
    }
}

pub type TlsStream<S> = StreamOwned<ClientConnection, S>;

/// This a wrapper to work equals
/// for a stream and a TLS stream
pub enum Stream<S> {
    /// Raw stream that implement Read + Write
    Raw(S),
    /// TLS Stream
    Ssl(TlsStream<S>),
}

impl<S: Read + Write> Stream<S> {
    /// Read exactly the number of bytes present in buffer
    ///
    /// # Example
    /// ```
    /// use rdp::model::link::Stream;
    /// use std::io::Cursor;
    /// let mut s = Stream::Raw(Cursor::new(vec![1, 2, 3]));
    /// let mut result = [0, 0];
    /// s.read_exact(&mut result).unwrap();
    /// assert_eq!(result, [1, 2])
    /// ```
    pub fn read_exact(&mut self, buf: &mut [u8]) -> RdpResult<()> {
        match self {
            Stream::Raw(e) => e.read_exact(buf)?,
            Stream::Ssl(e) => e.read_exact(buf)?,
        };
        Ok(())
    }

    /// Read all available buffer
    ///
    /// # Example
    /// ```
    /// use rdp::model::link::Stream;
    /// use std::io::Cursor;
    /// let mut s = Stream::Raw(Cursor::new(vec![1, 2, 3]));
    /// let mut result = [0, 0, 0, 0];
    /// s.read(&mut result).unwrap();
    /// assert_eq!(result, [1, 2, 3, 0])
    /// ```
    pub fn read(&mut self, buf: &mut [u8]) -> RdpResult<usize> {
        match self {
            Stream::Raw(e) => Ok(e.read(buf)?),
            Stream::Ssl(e) => Ok(e.read(buf)?),
        }
    }

    /// Write all buffer to the stream
    ///
    /// # Example
    /// ```
    /// use rdp::model::link::Stream;
    /// use std::io::Cursor;
    /// let mut s = Stream::Raw(Cursor::new(vec![]));
    /// let result = [1, 2, 3, 4];
    /// s.write(&result).unwrap();
    /// if let Stream::Raw(r) = s {
    ///     assert_eq!(r.into_inner(), [1, 2, 3, 4])
    /// }
    /// else {
    ///     panic!("invalid")
    /// }
    /// ```
    pub fn write(&mut self, buffer: &[u8]) -> RdpResult<usize> {
        Ok(match self {
            Stream::Raw(e) => e.write(buffer)?,
            Stream::Ssl(e) => e.write(buffer)?,
        })
    }

    /// Shutdown the stream
    /// Only works when stream is a SSL stream
    pub fn shutdown(&mut self) -> RdpResult<()> {
        if let Stream::Ssl(stream) = self {
            stream.conn.send_close_notify();
            stream.flush()?;
        }
        Ok(())
    }
}

/// Link layer is a wrapper around TCP or SSL stream
/// It can swicth from TCP to SSL
pub struct Link<S> {
    stream: Stream<S>,
}

impl<S: Read + Write> Link<S> {
    /// Create a new link layer from a Stream
    ///
    /// # Example
    /// ```no_run
    /// use rdp::model::link::{Link, Stream};
    /// use std::io::Cursor;
    /// use std::net::{TcpStream, SocketAddr};
    /// let link = Link::new(Stream::Raw(Cursor::new(vec![])));
    /// let addr = "127.0.0.1:3389".parse::<SocketAddr>().unwrap();
    /// let link_tcp = Link::new(Stream::Raw(TcpStream::connect(&addr).unwrap()));
    /// ```
    pub fn new(stream: Stream<S>) -> Self {
        Link { stream }
    }

    /// This method is designed to write a Message
    /// either for TCP or SSL stream
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # use rdp::model::data::{Component, U32};
    /// # use rdp::model::link::{Link, Stream};
    /// # use std::io::Cursor;
    /// # fn main() {
    ///     let mut link = Link::new(Stream::Raw(Cursor::new(vec![])));
    ///     link.write(&component![
    ///         "foo" => U32::LE(1)
    ///     ]).unwrap();
    ///
    ///     if let Stream::Raw(r) = link.get_stream() {
    ///         assert_eq!(r.into_inner(), [1, 0, 0, 0])
    ///     }
    ///     else {
    ///         panic!("invalid")
    ///     }
    /// # }
    /// ```
    pub fn write(&mut self, message: &dyn Message) -> RdpResult<()> {
        let mut buffer = Cursor::new(Vec::new());
        message.write(&mut buffer)?;
        self.stream.write(buffer.into_inner().as_slice())?;
        Ok(())
    }

    /// This function will block until the expected size will be read
    ///
    /// # Example
    /// ```
    /// use rdp::model::link::{Link, Stream};
    /// use std::io::Cursor;
    /// let mut link = Link::new(Stream::Raw(Cursor::new(vec![0, 1, 2])));
    /// assert_eq!(link.read(2).unwrap(), [0, 1])
    /// ```
    pub fn read(&mut self, expected_size: usize) -> RdpResult<Vec<u8>> {
        if expected_size == 0 {
            let mut buffer = vec![0; 1500];
            let size = self.stream.read(&mut buffer)?;
            buffer.resize(size, 0);
            Ok(buffer)
        } else {
            let mut buffer = vec![0; expected_size];
            self.stream.read_exact(&mut buffer)?;
            Ok(buffer)
        }
    }

    /// Start a ssl connection from a raw stream
    ///
    /// # Example
    /// ```no_run
    /// use rdp::model::link::{Link, Stream};
    /// use std::net::{TcpStream, SocketAddr};
    /// let addr = "127.0.0.1:3389".parse::<SocketAddr>().unwrap();
    /// let link_tcp = Link::new(Stream::Raw(TcpStream::connect(&addr).unwrap()));
    /// let link_ssl = link_tcp.start_ssl(false).unwrap();
    /// ```
    pub fn start_ssl(self, check_certificate: bool) -> RdpResult<Link<S>> {
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
        let conn = ClientConnection::new(arc, server_name)?;

        if let Stream::Raw(stream) = self.stream {
            let owned = TlsStream::new(conn, stream);
            return Ok(Link::new(Stream::Ssl(owned)));
        }
        Err(Error::RdpError(RdpError::new(
            RdpErrorKind::NotImplemented,
            "start_ssl on ssl stream is forbidden",
        )))
    }

    /// Retrive the peer certificate
    /// Use by the NLA authentication protocol
    /// to avoid MITM attack
    /// # Example
    /// ```no_run
    /// use rdp::model::link::{Link, Stream};
    /// use std::net::{TcpStream, SocketAddr};
    /// let addr = "127.0.0.1:3389".parse::<SocketAddr>().unwrap();
    /// let link_tcp = Link::new(Stream::Raw(TcpStream::connect(&addr).unwrap()));
    /// let link_ssl = link_tcp.start_ssl(false).unwrap();
    /// let certificate = link_ssl.get_peer_certificate().unwrap().unwrap();
    /// ```
    pub fn get_peer_certificate(&self) -> RdpResult<Option<Certificate>> {
        if let Stream::Ssl(stream) = &self.stream {
            if let Some(certs) = stream.conn.peer_certificates() {
                if let Some(cert) = certs.first() {
                    Ok(Some(cert.clone()))
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
        } else {
            Err(Error::RdpError(RdpError::new(
                RdpErrorKind::InvalidData,
                "get peer certificate on non ssl link is impossible",
            )))
        }
    }

    /// Close the stream
    /// Only works on SSL Stream
    pub fn shutdown(&mut self) -> RdpResult<()> {
        self.stream.shutdown()
    }

    #[cfg(feature = "integration")]
    pub fn get_stream(self) -> Stream<S> {
        self.stream
    }
}
