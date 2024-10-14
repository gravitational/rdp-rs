use num_enum::{TryFromPrimitive, TryFromPrimitiveError};
use std::fmt;
use std::io::Error as IoError;
use std::string::String;
use uuid;
use yasna::ASN1Error;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum RdpErrorKind {
    /// Unexpected data
    InvalidData,
    /// Respond from server or client is not valid
    InvalidRespond,
    /// Features not implemented
    NotImplemented,
    /// During connection sequence
    /// A security level is negotiated
    /// If no level can be defined a ProtocolNegFailure is emitted
    ProtocolNegFailure,
    /// Protocol automata transition is not expected
    InvalidAutomata,
    /// A security protocol
    /// selected was not handled by rdp-rs
    InvalidProtocol,
    /// All messages in rdp-rs
    /// are based on Message trait
    /// To retrieve the original data we used
    /// a visitor pattern. If the expected
    /// type is not found an InvalidCast error is emited
    InvalidCast,
    /// If an expected value is not equal
    InvalidConst,
    /// During security exchange some
    /// checksum are computed
    InvalidChecksum,
    InvalidOptionalField,
    InvalidSize,
    /// A possible Man In The Middle attack
    /// detected during NLA Authentication
    PossibleMITM,
    /// Some channel or user can be rejected
    /// by server during connection step
    RejectedByServer,
    /// Disconnect receive from server
    Disconnect,
    /// Indicate an unknown field
    Unknown,
    UnexpectedType,
}

/// ProtocolNegFailureCode defines the failure codes
/// for the RDP Negotiation Failure message (2.2.1.2.2).
/// It is sent by the server to inform the client of a failure
/// that has occurred while preparing security for the connection.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ProtocolNegFailureCode {
    Unknown(u32),
    SslRequiredByServer,
    SslNotAllowedByServer,
    SslCertNotOnServer,
    InconsistentFlags,
    HybridRequiredByServer,
    SslWithUserAuthRequiredByServer,
}

impl ProtocolNegFailureCode {
    pub fn from_code(code: u32) -> Self {
        match code {
            1 => ProtocolNegFailureCode::SslRequiredByServer,
            2 => ProtocolNegFailureCode::SslNotAllowedByServer,
            3 => ProtocolNegFailureCode::SslCertNotOnServer,
            4 => ProtocolNegFailureCode::InconsistentFlags,
            5 => ProtocolNegFailureCode::HybridRequiredByServer,
            6 => ProtocolNegFailureCode::SslWithUserAuthRequiredByServer,
            code => ProtocolNegFailureCode::Unknown(code),
        }
    }
}

impl fmt::Display for ProtocolNegFailureCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ProtocolNegFailureCode::SslRequiredByServer =>
                    "the server requires that the client support enhanced RDP Security with TLS or CredSSP"
                        .into(),
                ProtocolNegFailureCode::SslNotAllowedByServer =>
                    "the server is configured to only use standard RDP security mechanisms and does not support external security protocols"
                        .into(),
                ProtocolNegFailureCode::SslCertNotOnServer =>
                    "the server does not possess a valid authentication certificate and cannot initialize the external security protocol provider"
                        .into(),
                ProtocolNegFailureCode::InconsistentFlags =>
                    "the list of requested security protocols is not consistent with the current security protocol in effect"
                        .into(),
                ProtocolNegFailureCode::HybridRequiredByServer =>
                    "the server requires that the client support enhanced RDP security with CredSSP"
                        .into(),
                ProtocolNegFailureCode::SslWithUserAuthRequiredByServer =>
                    "the server requires that the client support enhanced RDP security with TLS and certificate-based client authentication"
                        .into(),
                ProtocolNegFailureCode::Unknown(code) =>
                    format!("unknown negotiation failure {}", code),
            }
        )
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct RdpError {
    /// Kind of error
    kind: RdpErrorKind,
    /// Associated message of the context
    message: String,
}

impl RdpError {
    /// create a new RDP error
    /// # Example
    /// ```
    /// use rdp::model::error::{RdpError, RdpErrorKind};
    /// let error = RdpError::new(RdpErrorKind::Disconnect, "disconnected");
    /// ```
    pub fn new(kind: RdpErrorKind, message: &str) -> Self {
        RdpError {
            kind,
            message: String::from(message),
        }
    }

    /// Return the kind of error
    ///
    /// # Example
    /// ```
    /// use rdp::model::error::{RdpError, RdpErrorKind};
    /// let error = RdpError::new(RdpErrorKind::Disconnect, "disconnected");
    /// assert_eq!(error.kind(), RdpErrorKind::Disconnect)
    /// ```
    pub fn kind(&self) -> RdpErrorKind {
        self.kind
    }
}

#[derive(Debug)]
pub enum Error {
    /// RDP error
    RdpError(RdpError),
    /// All kind of IO error
    Io(IoError),
    /// SSL handshake error
    SslHandshakeError,
    /// SSL error
    SslError,
    /// ASN1 parser error
    ASN1Error(ASN1Error),
    /// try error
    TryError(String),
    // All kind of parse error
    FromError(String),
}

impl From<uuid::Error> for Error {
    fn from(_e: uuid::Error) -> Self {
        Error::FromError(String::from("agent identifier is not a valid UUID"))
    }
}

/// From IO Error
impl From<IoError> for Error {
    fn from(e: IoError) -> Self {
        Error::Io(e)
    }
}

impl From<ASN1Error> for Error {
    fn from(e: ASN1Error) -> Error {
        Error::ASN1Error(e)
    }
}

impl<T: TryFromPrimitive> From<TryFromPrimitiveError<T>> for Error {
    fn from(_: TryFromPrimitiveError<T>) -> Self {
        Error::RdpError(RdpError::new(
            RdpErrorKind::InvalidCast,
            "Invalid enum conversion",
        ))
    }
}

impl From<std::num::TryFromIntError> for Error {
    fn from(err: std::num::TryFromIntError) -> Self {
        Error::TryError(err.to_string())
    }
}

pub type RdpResult<T> = Result<T, Error>;

/// Try options is waiting try trait for the next rust
#[macro_export]
macro_rules! try_option {
    ($val: expr, $expr: expr) => {
        if let Some(x) = $val {
            Ok(x)
        } else {
            Err(Error::RdpError(RdpError::new(
                RdpErrorKind::InvalidOptionalField,
                $expr,
            )))
        }
    };
}

#[macro_export]
macro_rules! try_let {
    ($ident: path, $val: expr) => {
        if let $ident(x) = $val {
            Ok(x)
        } else {
            Err(Error::RdpError(RdpError::new(
                RdpErrorKind::InvalidCast,
                "Invalid Cast",
            )))
        }
    };
}
