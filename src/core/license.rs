use crate::core::mcs;
use crate::core::tpkt;
use crate::model::data::{
    Check, Component, DataType, DynOption, Message, MessageOption, Trame, U16, U32,
};
use crate::model::error::{Error, RdpError, RdpErrorKind, RdpResult};
use crate::model::rnd::random;
use crate::model::unicode;
use num_enum::TryFromPrimitive;
use std::convert::TryFrom;
use std::ffi::CString;
use std::io::{self, Cursor, Read, Write};

use crate::core::sec::SecurityFlag;

use md5::Digest;
use num_bigint::BigUint;
use rc4::{Key, Rc4};
use rc4::{KeyInit, StreamCipher};
use ring::digest;
use rsa::{PublicKeyParts, RsaPublicKey};
use uuid::Uuid;
use x509_parser::{certificate::X509Certificate, prelude::FromDer};

const SIGNATURE_ALG_RSA: u32 = 0x00000001;
const KEY_EXCHANGE_ALG_RSA: u32 = 0x00000001;
const CERT_CHAIN_VERSION_1: u32 = 0x00000001;
const CERT_CHAIN_VERSION_2: u32 = 0x00000002;
const CERT_CHAIN_VERSION_MASK: u32 = 0x7FFFFFFF;
const PLATFORM_CHALLENGE_VERSION: u16 = 0x0100;
const CLIENT_RANDOM_SIZE: usize = 32;
const PREMASTER_RANDOM_SIZE: usize = 48;

#[repr(u8)]
#[allow(dead_code)]
enum Preambule {
    PreambleVersion20 = 0x2,
    PreambleVersion30 = 0x3,
    ExtendedErrorMsgSupported = 0x80,
}

#[repr(u16)]
#[allow(dead_code)]
enum PlatformChallengeType {
    Win32 = 0x0100,
    Win16 = 0x0200,
    WinCE = 0x0300,
    Other = 0xFF00,
}

#[repr(u16)]
#[allow(dead_code)]
enum LicenseDetailLevel {
    Simple = 0x0001,
    Moderate = 0x0002,
    Detail = 0x0003,
}

/// All type of message
/// which can follow a license preamble
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/73170ca2-5f82-4a2d-9d1b-b439f3d8dadc
#[repr(u8)]
#[derive(Debug, TryFromPrimitive)]
pub enum MessageType {
    LicenseRequest = 0x01,
    PlatformChallenge = 0x02,
    NewLicense = 0x03,
    UpgradeLicense = 0x04,
    LicenseInfo = 0x12,
    NewLicenseRequest = 0x13,
    PlatformChallengeResponse = 0x15,
    ErrorAlert = 0xFF,
}

/// Error code of the license automata
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/f18b6c9f-f3d8-4a0e-8398-f9b153233dca?redirectedfrom=MSDN
#[repr(u32)]
#[derive(PartialEq, Eq, TryFromPrimitive)]
pub enum ErrorCode {
    ErrInvalidServerCertificate = 0x00000001,
    ErrNoLicense = 0x00000002,
    ErrInvalidScope = 0x00000004,
    ErrNoLicenseServer = 0x00000006,
    StatusValidClient = 0x00000007,
    ErrInvalidClient = 0x00000008,
    ErrInvalidProductid = 0x0000000B,
    ErrInvalidMessageLen = 0x0000000C,
    ErrInvalidMac = 0x00000003,
}

/// All valid state transition available
/// for license automata
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/f18b6c9f-f3d8-4a0e-8398-f9b153233dca
#[repr(u32)]
#[derive(PartialEq, Eq, TryFromPrimitive)]
pub enum StateTransition {
    StTotalAbort = 0x00000001,
    StNoTransition = 0x00000002,
    StResetPhaseToStart = 0x00000003,
    StResendLastMessage = 0x00000004,
}

#[repr(u16)]
#[derive(TryFromPrimitive)]
pub enum BlobType {
    Data = 0x0001,
    Random = 0x0002,
    Certificate = 0x0003,
    Error = 0x0004,
    EncryptedData = 0x0009,
    KeyExchgAlg = 0x000D,
    Scope = 0x000E,
    ClientUserName = 0x000F,
    ClientMachineName = 0x0010,
}

#[repr(u32)]
#[derive(TryFromPrimitive)]
pub enum ClientImageId {
    Microsoft = 0x00010000,
    Citrix = 0x00020000,
}

#[repr(u32)]
#[derive(TryFromPrimitive)]
pub enum ClientOsId {
    WinNt351 = 0x01000000,
    WinNt40 = 0x02000000,
    WinNt50 = 0x03000000,
    WinNtPost52 = 0x04000000,
}

pub enum LicenseMessage {
    NewLicense(NewLicense),
    LicenseRequest(ServerLicenseRequest),
    PlatformChallenge(PlatformChallenge),
    UpgradeLicense(UpgradeLicense),
    ErrorAlert(ErrorAlert),
}

impl LicenseMessage {
    fn new(payload: tpkt::Payload) -> RdpResult<Self> {
        let mut stream = try_let!(tpkt::Payload::Raw, payload)?;
        let mut security_header = component![
            "securityFlag" => U16::LE(0),
            "securityFlagHi" => U16::LE(0)
        ];
        security_header.read(&mut stream)?;
        if (cast!(DataType::U16, security_header["securityFlag"])?
            & SecurityFlag::SecLicensePkt as u16)
            == 0
        {
            return Err(Error::RdpError(RdpError::new(
                RdpErrorKind::InvalidData,
                "SEC: Invalid Licence packet",
            )));
        }

        let mut license_message = component![
            "bMsgtype" => 0_u8,
            "flag" => Check::new(Preambule::PreambleVersion30 as u8),
            "wMsgSize" => DynOption::new(U16::LE(0), |size| MessageOption::Size("message".to_string(), size.inner() as usize - 4)),
            "message" => Vec::<u8>::new()
        ];

        license_message.read(&mut stream)?;
        let msg_type = cast!(DataType::U8, license_message["bMsgtype"])?;
        let mut msg_data = Cursor::new(cast!(DataType::Slice, license_message["message"])?);

        match MessageType::try_from(cast!(DataType::U8, license_message["bMsgtype"])?)? {
            MessageType::NewLicense => Ok(Self::NewLicense(NewLicense::from_bytes(&mut msg_data)?)),
            MessageType::LicenseRequest => Ok(Self::LicenseRequest(
                ServerLicenseRequest::from_bytes(&mut msg_data)?,
            )),
            MessageType::PlatformChallenge => Ok(Self::PlatformChallenge(
                PlatformChallenge::from_bytes(&mut msg_data)?,
            )),
            MessageType::UpgradeLicense => Ok(Self::UpgradeLicense(UpgradeLicense::from_bytes(
                &mut msg_data,
            )?)),
            MessageType::ErrorAlert => Ok(Self::ErrorAlert(ErrorAlert::from_bytes(&mut msg_data)?)),
            _ => Err(Error::RdpError(RdpError::new(
                RdpErrorKind::NotImplemented,
                &format!("Licensing nego not implemented. bMsgtype: {msg_type:?}"),
            ))),
        }
    }
}

pub enum ServerCertificate {
    Proprietary(RsaPublicKey),
    X509(RsaPublicKey),
}

impl ServerCertificate {
    fn from_bytes(raw: &mut dyn Read) -> RdpResult<Self> {
        let mut binary_blob_server_certificate = component![
            "dwVersion" => U32::LE(0),
            "certData" => Vec::<u8>::new()
        ];
        binary_blob_server_certificate.read(raw)?;
        let cert_version = cast!(DataType::U32, binary_blob_server_certificate["dwVersion"])?;
        let mut cert_data = cast!(DataType::Slice, binary_blob_server_certificate["certData"])?;

        match cert_version & CERT_CHAIN_VERSION_MASK {
            CERT_CHAIN_VERSION_1 => {
                let mut message = component![
                    "dwSigAlgId" => U32::LE(0),
                    "dwKeyAlgId" => U32::LE(0),
                    "wPublicKeyBlobType" => U16::LE(0),
                    "wPublicKeyBlobLen" => DynOption::new(U16::LE(0), | size | MessageOption::Size("PublicKeyBlob".to_string(), size.inner() as usize)),
                    "PublicKeyBlob" => component![
                        "magic" => U32::LE(0),
                        "keylen" => DynOption::new(U32::LE(0), | size | MessageOption::Size("modulus".to_string(), size.inner() as usize - 8)),
                        "bitlen" => U32::LE(0),
                        "datalen" => U32::LE(0),
                        "pubExp" => U32::LE(0),
                        "modulus" => Vec::<u8>::new(),
                        "padding" => vec![0_u8; 8]
                    ],
                    "wSignatureBlobType" => U16::LE(0),
                    "wSignatureBlobLen" => DynOption::new(U16::LE(0), | size | MessageOption::Size("SignatureBlob".to_string(), size.inner() as usize)),
                    "SignatureBlob" => Vec::<u8>::new()
                ];

                message.read(&mut cert_data)?;

                let sig_alg_id = cast!(DataType::U32, message["dwSigAlgId"])?;
                let key_alg_id = cast!(DataType::U32, message["dwKeyAlgId"])?;
                if sig_alg_id != SIGNATURE_ALG_RSA && key_alg_id != KEY_EXCHANGE_ALG_RSA {
                    return Err(Error::RdpError(RdpError::new(
                        RdpErrorKind::NotImplemented,
                        &format!(
                            "unsupported signature or key algorithm, dwSigAlgId={sig_alg_id} dwKeyAlgId={key_alg_id}"
                        ),
                    )));
                }
                let public_key_blob = cast!(DataType::Component, message["PublicKeyBlob"])?;
                let pubexp = cast!(DataType::U32, public_key_blob["pubExp"])?;
                let modulus = cast!(DataType::Slice, public_key_blob["modulus"])?;
                let n = rsa::BigUint::from_bytes_le(modulus);
                let e = rsa::BigUint::from_slice(&[pubexp]);
                Ok(Self::Proprietary(RsaPublicKey::new(n, e).unwrap()))
            }
            CERT_CHAIN_VERSION_2 => {
                let mut num_cert_blobs = U32::LE(0);
                num_cert_blobs.read(&mut cert_data)?;
                let num_cert_blobs = cast!(DataType::U32, num_cert_blobs)?;

                if num_cert_blobs < 2 {
                    return Err(Error::RdpError(RdpError::new(
                        RdpErrorKind::InvalidData,
                        &format!("invalid number of certificates in the chain. expected minimum 2, found: {num_cert_blobs}"),
                    )));
                }
                let mut certificates: Vec<Vec<u8>> = Vec::with_capacity(num_cert_blobs as usize);
                for _ in 0..num_cert_blobs {
                    let mut cert_blob = component![
                        "cbCert" => DynOption::new(U32::LE(0), | size | MessageOption::Size("abCert".to_string(), size.inner() as usize)),
                        "abCert" => Vec::<u8>::new()
                    ];
                    cert_blob.read(&mut cert_data)?;
                    certificates.push(cast!(DataType::Slice, cert_blob["abCert"])?.to_vec());
                }

                Self::from_der(&certificates[certificates.len() - 1])
            }
            _ => Err(Error::RdpError(RdpError::new(
                RdpErrorKind::NotImplemented,
                "Invalid certificate version",
            ))),
        }
    }

    fn from_der(data: &[u8]) -> RdpResult<Self> {
        let (_, mut x509) = X509Certificate::from_der(data).map_err(|_| {
            Error::RdpError(RdpError::new(
                RdpErrorKind::InvalidData,
                "invalid X509 certificate",
            ))
        })?;

        // Some Windows servers uses certificates with old and invalid OIDs, e.g. Oid(1.3.14.3.2.15)
        // and we can't parse it so we have to fix it
        x509.tbs_certificate.subject_pki.algorithm.algorithm =
            oid_registry::OID_PKCS1_RSAENCRYPTION;
        let public_key = x509.tbs_certificate.subject_pki.parsed().map_err(|_| {
            Error::RdpError(RdpError::new(
                RdpErrorKind::InvalidData,
                "can't parse X509 certificate",
            ))
        })?;

        let rsa_public_key = match public_key {
            x509_parser::public_key::PublicKey::RSA(key) => RsaPublicKey::new(
                rsa::BigUint::from_bytes_be(key.modulus),
                rsa::BigUint::from_bytes_be(key.exponent),
            )
            .map_err(|_| {
                Error::RdpError(RdpError::new(
                    RdpErrorKind::InvalidData,
                    "can't get RSA certificate from the X509 certificate",
                ))
            })?,
            _ => {
                return Err(Error::RdpError(RdpError::new(
                    RdpErrorKind::InvalidData,
                    "invalid type of certificate",
                )))
            }
        };

        Ok(Self::X509(rsa_public_key))
    }
}

pub struct NewLicense {
    mac_data: Vec<u8>,
    encrypted_license_data: Vec<u8>,
}

impl NewLicense {
    fn from_bytes(raw: &mut dyn Read) -> RdpResult<Self> {
        let mut message = component![
            "EncryptedLicenseInfo" => component![
                "wBlobType" => U16::LE(0),
                "wBlobLen" => DynOption::new(U16::LE(0), | size | MessageOption::Size("blobData".to_string(), size.inner() as usize)),
                "blobData" => Vec::<u8>::new()
            ],
            "MACData" => vec![0_u8; 16]
        ];

        message.read(raw)?;
        let encrypted_license_data =
            cast!(DataType::Slice, message["EncryptedLicenseInfo"])?.to_vec();
        let mac_data = cast!(DataType::Slice, message["MACData"])?.to_vec();
        Ok(Self {
            encrypted_license_data,
            mac_data,
        })
    }
}

pub struct ErrorAlert {
    code: ErrorCode,
    state_transition: StateTransition,
}

impl ErrorAlert {
    fn from_bytes(raw: &mut dyn Read) -> RdpResult<Self> {
        let mut message = component![
        "dwErrorCode" => U32::LE(0),
        "dwStateTransition" => U32::LE(0),
        "blob" => component![
            "wBlobType" => U16::LE(0),
            "wBlobLen" => DynOption::new(U16::LE(0), | size | MessageOption::Size("blobData".to_string(), size.inner() as usize)),
            "blobData" => Vec::<u8>::new()
        ]];
        message.read(raw)?;

        let code = ErrorCode::try_from(cast!(DataType::U32, message["dwErrorCode"])?)?;
        let state_transition =
            StateTransition::try_from(cast!(DataType::U32, message["dwStateTransition"])?)?;
        Ok(Self {
            code,
            state_transition,
        })
    }

    fn is_valid(&self) -> RdpResult<()> {
        if self.code == ErrorCode::StatusValidClient
            && self.state_transition == StateTransition::StNoTransition
        {
            Ok(())
        } else {
            Err(Error::RdpError(RdpError::new(
                RdpErrorKind::InvalidRespond,
                "server reject license",
            )))
        }
    }
}

struct BinaryBlob {
    blob_type: BlobType,
    data: Vec<u8>,
}

impl BinaryBlob {
    fn new(blob_type: BlobType, data: Vec<u8>) -> Self {
        Self { blob_type, data }
    }

    fn component(self) -> Component {
        component![
            "wBlobType" => U16::LE(self.blob_type as u16),
            "wBlobLen" => U16::LE(self.data.len() as u16),
            "blobData" => self.data
        ]
    }
}

#[allow(dead_code)]
pub struct UpgradeLicense {
    mac_data: Vec<u8>,
    encrypted_license_data: Vec<u8>,
}

impl UpgradeLicense {
    fn from_bytes(raw: &mut dyn Read) -> RdpResult<Self> {
        let mut message = component![
            "EncryptedLicenseInfo" => component![
                "wBlobType" => U16::LE(0),
                "wBlobLen" => DynOption::new(U16::LE(0), | size | MessageOption::Size("blobData".to_string(), size.inner() as usize)),
                "blobData" => Vec::<u8>::new()
            ],
            "MACData" => vec![0_u8; 16]
        ];
        message.read(raw)?;

        let encrypted_license_data =
            cast!(DataType::Slice, message["EncryptedLicenseInfo"])?.to_vec();
        let mac_data = cast!(DataType::Slice, message["MACData"])?.to_vec();

        Ok(Self {
            encrypted_license_data,
            mac_data,
        })
    }

    // TODO(zmb3): remove this exception
    #[allow(dead_code)]
    fn decrypted_license(&self, session_encryption_data: &SessionEncryptionData) -> Vec<u8> {
        session_encryption_data.decrypt_message(&self.encrypted_license_data)
    }
}

/// License data that has been obtained from the sever
#[allow(dead_code)]
struct License {
    data: Vec<u8>,
}

impl License {
    fn new(
        session_encryption_data: &SessionEncryptionData,
        new_license: &NewLicense,
    ) -> RdpResult<Self> {
        let mut rc4 = Rc4::new(Key::<rc4::consts::U16>::from_slice(
            &session_encryption_data.license_encryption_key,
        ));

        let mut data: Vec<u8> = new_license.encrypted_license_data.clone();
        rc4.apply_keystream(&mut data);

        if session_encryption_data.generate_mac_data(&data) != new_license.mac_data {
            return Err(Error::RdpError(RdpError::new(
                RdpErrorKind::InvalidData,
                "license MAC is different than MAC from encrypted message",
            )));
        }
        Ok(Self { data })
    }
}

pub struct PlatformChallenge {
    mac_data: Vec<u8>,
    encrypted_platform_challenge: Vec<u8>,
}

impl PlatformChallenge {
    fn from_bytes(raw: &mut dyn Read) -> RdpResult<Self> {
        let mut message = component![
                "ConnectFlags" => U32::LE(0),
                "EncryptedPlatformChallenge" => component![
                    "wBlobType" => U16::LE(0),
                    "wBlobLen" => DynOption::new(U16::LE(0), | size | MessageOption::Size("blobData".to_string(), size.inner() as usize)),
                    "blobData" => Vec::<u8>::new()
                ],
                "MACData" => vec![0_u8; 16]
        ];
        message.read(raw)?;
        Ok(Self {
            mac_data: cast!(DataType::Slice, message["MACData"])?.to_vec(),
            encrypted_platform_challenge: cast!(
                DataType::Slice,
                cast!(DataType::Component, message["EncryptedPlatformChallenge"])?["blobData"]
            )?
            .to_vec(),
        })
    }
}

#[allow(dead_code)]
pub struct ServerLicenseRequest {
    server_random: Vec<u8>,
    certificate: ServerCertificate,

    version_major: u16,
    version_minor: u16,

    company_name: String,
    product_id: String,
}

impl ServerLicenseRequest {
    fn from_bytes(raw: &mut dyn Read) -> RdpResult<Self> {
        let mut message = component![
            "ServerRandom" => vec![0; 32],
            "dwVersion" => U32::LE(0),
            "cbCompanyName" => DynOption::new(U32::LE(0), | size | MessageOption::Size("pbCompanyName".to_string(), size.inner() as usize)),
            "pbCompanyName" => Vec::<u8>::new(),
            "cbProductId" => DynOption::new(U32::LE(0), | size | MessageOption::Size("pbProductId".to_string(), size.inner() as usize)),
            "pbProductId" => Vec::<u8>::new(),
            "KeyExchangeList" => component![
                "wBlobType" => U16::LE(0),
                "wBlobLen" => DynOption::new(U16::LE(0), | size | MessageOption::Size("blobData".to_string(), size.inner() as usize)),
                "blobData" => Vec::<u8>::new()
            ],
            "ServerCertificate" => component![
                "wBlobType" => U16::LE(0),
                "wBlobLen" => DynOption::new(U16::LE(0), | size | MessageOption::Size("blobData".to_string(), size.inner() as usize)),
                "blobData" => Vec::<u8>::new()
            ],
            "ScopeCount" => DynOption::new(U32::LE(0), | size | MessageOption::Size("ScopeArray".to_string(), size.inner() as usize)),
            "ScopeArray" => Vec::<u8>::new()
        ];

        message.read(raw)?;
        let server_random = cast!(DataType::Slice, message["ServerRandom"])?;
        let version = cast!(DataType::U32, message["dwVersion"])?;
        let server_certificate = cast!(DataType::Component, message["ServerCertificate"])?;
        let mut blob_data = cast!(DataType::Slice, server_certificate["blobData"])?;

        Ok(Self {
            server_random: Vec::from(server_random),
            certificate: ServerCertificate::from_bytes(&mut blob_data)?,
            company_name: unicode::parse_utf16le(cast!(DataType::Slice, message["pbCompanyName"])?),
            product_id: unicode::parse_utf16le(cast!(DataType::Slice, message["pbProductId"])?),
            version_major: (version >> 16) as u16,
            version_minor: (version & 0xFFFF) as u16,
        })
    }
}

struct ClientNewLicense<'a> {
    session_encryption_data: &'a SessionEncryptionData,
    client_machine: CString,
    username: CString,
}

impl<'a> ClientNewLicense<'a> {
    fn new(
        session_encryption_data: &'a SessionEncryptionData,
        username: CString,
        client_machine: CString,
    ) -> RdpResult<Self> {
        Ok(Self {
            session_encryption_data,
            username,
            client_machine,
        })
    }

    fn to_bytes(&self) -> RdpResult<Vec<u8>> {
        let client_new_license_request = component![
            "PreferredKeyExchangeAlg" => U32::LE(KEY_EXCHANGE_ALG_RSA),
            "PlatformId" => U32::LE(ClientOsId::WinNtPost52 as u32 | ClientImageId::Microsoft as u32),
            "ClientRandom" => self.session_encryption_data.client_random.clone(),
            "EncryptedPreMasterSecret" => BinaryBlob::new(BlobType::Random, self.session_encryption_data.encrypt_message(&self.session_encryption_data.premaster_secret)?).component(),
            "ClientUserName" => BinaryBlob::new(BlobType::ClientUserName, self.username.to_bytes_with_nul().to_owned()).component(),
            "ClientMachineName" => BinaryBlob::new(BlobType::ClientMachineName, self.client_machine.to_bytes_with_nul().to_owned()).component()
        ];

        let mut buf: Vec<u8> = Vec::with_capacity(client_new_license_request.length() as usize);
        client_new_license_request.write(&mut buf)?;
        Ok(buf)
    }
}

struct ClientPlatformChallenge<'a> {
    session_encryption_data: &'a SessionEncryptionData,
    platform_challenge_data: Vec<u8>,
    client_hwid: [u8; 16],
}

impl<'a> ClientPlatformChallenge<'a> {
    fn new(
        platform_challenge: PlatformChallenge,
        session_encryption_data: &'a SessionEncryptionData,
        client_hwid: [u8; 16],
    ) -> RdpResult<Self> {
        let platform_challenge_data = session_encryption_data
            .decrypt_message(&platform_challenge.encrypted_platform_challenge);
        if session_encryption_data.generate_mac_data(&platform_challenge_data)
            != platform_challenge.mac_data
        {
            return Err(Error::RdpError(RdpError::new(
                RdpErrorKind::InvalidData,
                "platform challenge MAC is different than MAC from encrypted message",
            )));
        }

        Ok(Self {
            session_encryption_data,
            platform_challenge_data,
            client_hwid,
        })
    }

    fn to_bytes(&self) -> RdpResult<Vec<u8>> {
        let platform_challenge_response_data = component![
            "wVersion" => U16::LE(PLATFORM_CHALLENGE_VERSION),
            "wClientType" => U16::LE(PlatformChallengeType::Other as u16),
            "wLicenseDetailLevel" => U16::LE(LicenseDetailLevel::Detail as u16),
            "cbChallenge" => U16::LE(self.platform_challenge_data.len() as u16),
            "pbChallenge" => self.platform_challenge_data.clone()
        ];

        let client_hardware_identification = component![
            "PlatformId" => U32::LE(ClientOsId::WinNtPost52 as u32 | ClientImageId::Microsoft as u32),
            "client_hardware_id" => self.client_hwid.to_vec()
        ];

        let mut response_platform_challenge_response_data: Vec<u8> =
            Vec::with_capacity(platform_challenge_response_data.len());
        platform_challenge_response_data.write(&mut response_platform_challenge_response_data)?;
        let mut rc4 = Rc4::new(Key::<rc4::consts::U16>::from_slice(
            &self.session_encryption_data.license_encryption_key,
        ));

        rc4.apply_keystream(&mut response_platform_challenge_response_data);

        let mut response_client_hardware_identification_data =
            Vec::with_capacity(client_hardware_identification.length() as usize);
        client_hardware_identification.write(&mut response_client_hardware_identification_data)?;

        let mut rc4 = Rc4::new(Key::<rc4::consts::U16>::from_slice(
            &self.session_encryption_data.license_encryption_key,
        ));

        rc4.apply_keystream(&mut response_client_hardware_identification_data);

        // MD5 digest (MAC) generated over the Platform Challenge Response Data and decrypted Client Hardware Identification
        let mut mac_input = Vec::with_capacity(
            response_platform_challenge_response_data.len()
                + response_client_hardware_identification_data.len(),
        );
        mac_input.extend(&response_platform_challenge_response_data);
        mac_input.extend(&response_client_hardware_identification_data);

        let mac_data = self.session_encryption_data.generate_mac_data(&mac_input);

        let client_platform_challenge_response = component![
            "EncryptedPlatformChallengeResponse" => BinaryBlob::new(BlobType::EncryptedData, response_platform_challenge_response_data).component(),
            "EncryptedHWID" => BinaryBlob::new(BlobType::EncryptedData, response_client_hardware_identification_data).component(),
            "MACData" => mac_data
        ];

        let mut buf: Vec<u8> =
            Vec::with_capacity(client_platform_challenge_response.length() as usize);
        client_platform_challenge_response.write(&mut buf)?;
        Ok(buf)
    }
}

struct SessionEncryptionData {
    client_random: Vec<u8>,
    premaster_secret: Vec<u8>,
    mac_salt_key: Vec<u8>,
    license_encryption_key: Vec<u8>,
    rsa_public_key: RsaPublicKey,
}

impl SessionEncryptionData {
    fn new(
        client_random: Vec<u8>,
        server_random: Vec<u8>,
        premaster_secret: Vec<u8>,
        server_certificate: ServerCertificate,
    ) -> Self {
        let master_secret = Self::master_secret(&premaster_secret, &client_random, &server_random);
        let session_key_blob =
            Self::session_key_blob(&master_secret, &client_random, &server_random);
        let mac_salt_key = session_key_blob[..16].to_vec();
        let mut md5 = md5::Md5::new();
        md5.input([&session_key_blob[16..32], &client_random, &server_random].concat());
        let license_encryption_key = md5.result().to_vec();

        let rsa_public_key = match server_certificate {
            ServerCertificate::Proprietary(rsa) => rsa,
            ServerCertificate::X509(rsa) => rsa,
        };

        Self {
            client_random,
            premaster_secret,
            mac_salt_key,
            license_encryption_key,
            rsa_public_key,
        }
    }

    pub fn decrypt_message(&self, message: &[u8]) -> Vec<u8> {
        let mut buf: Vec<u8> = message.to_vec();
        let mut rc4 = Rc4::new(Key::<rc4::consts::U16>::from_slice(
            &self.license_encryption_key,
        ));
        rc4.apply_keystream(&mut buf);

        buf
    }

    pub fn encrypt_message(&self, message: &[u8]) -> io::Result<Vec<u8>> {
        let n = BigUint::from_bytes_be(&self.rsa_public_key.n().to_bytes_be());
        let e = BigUint::from_bytes_be(&self.rsa_public_key.e().to_bytes_be());
        let m = BigUint::from_bytes_le(message);
        let c = m.modpow(&e, &n);

        let mut encrypted = c.to_bytes_le();
        encrypted.extend_from_slice(&[0_u8; 8]);
        Ok(encrypted)
    }

    fn salted_hash(input: &[u8], salt: &[u8], salt1: &[u8], salt2: &[u8]) -> Vec<u8> {
        let mut md5 = md5::Md5::new();
        md5.input(
            [
                salt,
                digest::digest(
                    &digest::SHA1_FOR_LEGACY_USE_ONLY,
                    &[input, salt, salt1, salt2].concat(),
                )
                .as_ref(),
            ]
            .concat(),
        );
        md5.result().to_vec()
    }

    fn master_secret(
        premaster_secret: &[u8],
        client_random: &[u8],
        server_random: &[u8],
    ) -> Vec<u8> {
        [
            Self::salted_hash(b"A", premaster_secret, client_random, server_random),
            Self::salted_hash(b"BB", premaster_secret, client_random, server_random),
            Self::salted_hash(b"CCC", premaster_secret, client_random, server_random),
        ]
        .concat()
    }

    fn session_key_blob(
        master_secret: &[u8],
        client_random: &[u8],
        server_random: &[u8],
    ) -> Vec<u8> {
        [
            Self::salted_hash(b"A", master_secret, server_random, client_random),
            Self::salted_hash(b"BB", master_secret, server_random, client_random),
            Self::salted_hash(b"CCC", master_secret, server_random, client_random),
        ]
        .concat()
    }

    fn generate_mac_data(&self, data: &[u8]) -> Vec<u8> {
        let mut md5 = md5::Md5::new();
        md5.input(
            [
                &self.mac_salt_key[..],
                &[0x5c; 48][..], // pad2
                digest::digest(
                    &digest::SHA1_FOR_LEGACY_USE_ONLY,
                    &[
                        &self.mac_salt_key,
                        &[0x36; 40][..], // pad1
                        &(data.len() as u32).to_le_bytes(),
                        data,
                    ]
                    .concat(),
                )
                .as_ref(),
            ]
            .concat(),
        );
        md5.result().to_vec()
    }
}

/// ClientLicenseInfo is sent from the client to the server in cases
/// where the client already has an existing license issued to it.
struct ClientLicenseInfo<'a> {
    session_encryption_data: &'a SessionEncryptionData,
    license: &'a Vec<u8>,
    client_hwid: [u8; 16],
}

#[allow(dead_code)]
impl<'a> ClientLicenseInfo<'a> {
    fn new(
        session_encryption_data: &'a SessionEncryptionData,
        license: &'a Vec<u8>,
        client_hwid: [u8; 16],
    ) -> RdpResult<Self> {
        Ok(Self {
            session_encryption_data,
            license,
            client_hwid,
        })
    }

    fn to_bytes(&self) -> RdpResult<Vec<u8>> {
        let platform_id = U32::LE(ClientOsId::WinNtPost52 as u32 | ClientImageId::Microsoft as u32);

        let hardware_identification = component![
            "PlatformId" => platform_id,
            "client_hardware_id" => self.client_hwid.to_vec()
        ];
        let mut encrypted_hardware_identification =
            Vec::with_capacity(hardware_identification.length() as usize);
        hardware_identification.write(&mut encrypted_hardware_identification)?;

        // make a copy of the hardware identification info prior to encrypting it,
        // which will be used as input to the MAC
        let mac_input = encrypted_hardware_identification.clone();

        // now encrypt the data
        let mut rc4 = Rc4::new(Key::<rc4::consts::U16>::from_slice(
            &self.session_encryption_data.license_encryption_key,
        ));
        rc4.apply_keystream(&mut encrypted_hardware_identification);

        let request = component![
            "PreferredKeyExchangeAlg" => U32::LE(KEY_EXCHANGE_ALG_RSA),
            "PlatformId" => platform_id,
            "ClientRandom" => self.session_encryption_data.client_random.clone(),
            "EncryptedPreMasterSecret" => BinaryBlob::new(BlobType::Random, self.session_encryption_data.encrypt_message(&self.session_encryption_data.premaster_secret)?).component(),
            "LicenseInfo" => BinaryBlob::new(BlobType::Data, self.license.to_owned()).component(),
            "EncryptedHWID" => BinaryBlob::new(BlobType::EncryptedData, encrypted_hardware_identification).component(),
            "MACData" => self.session_encryption_data.generate_mac_data(&mac_input)
        ];

        let mut buf: Vec<u8> = Vec::with_capacity(request.length() as usize);
        request.write(&mut buf)?;
        Ok(buf)
    }
}

/// Wraps license message with security and preamble headers
fn license_response(message_type: MessageType, data: Vec<u8>) -> RdpResult<Vec<u8>> {
    let message = trame![
        U16::LE(SecurityFlag::SecLicensePkt as u16),
        U16::LE(0),
        component![
            "bMsgtype" => message_type as u8,
            "flag" => Check::new(Preambule::ExtendedErrorMsgSupported as u8 | Preambule::PreambleVersion30 as u8),
            "wMsgSize" => U16::LE(data.len() as u16 + 4),
            "message" => data
        ]
    ];

    let mut buf: Vec<u8> = Vec::with_capacity(message.length() as usize);
    message.write(&mut buf)?;
    Ok(buf)
}

pub fn client_connect<T: Read + Write>(
    mcs: &mut mcs::Client<T>,
    client_machine: &str, // must be a UUID
    username: &str,
) -> RdpResult<()> {
    // We use the UUID that identifies the client as both the client machine name,
    // and (in binary form) the hardware identifier for the client.
    let client_uuid = Uuid::try_parse(client_machine)?;

    let (channel, payload) = mcs.read()?;
    let session_encryption_data = match LicenseMessage::new(payload)? {
        // When we get the `NewLicense` message at the start of the
        // license flow it means that we don't have to continue
        // so we can return
        LicenseMessage::NewLicense(_) => return Ok(()),
        LicenseMessage::LicenseRequest(request) => {
            let session_encryption_data = SessionEncryptionData::new(
                random(CLIENT_RANDOM_SIZE),
                request.server_random,
                random(PREMASTER_RANDOM_SIZE),
                request.certificate,
            );
            let client_new_license_response = ClientNewLicense::new(
                &session_encryption_data,
                CString::new(client_machine).unwrap_or_else(|_| CString::new(".").unwrap()),
                CString::new(username).unwrap_or_else(|_| CString::new("default").unwrap()),
            )?;
            mcs.write(
                &channel,
                license_response(
                    MessageType::NewLicenseRequest,
                    client_new_license_response.to_bytes()?,
                )?,
            )?;
            session_encryption_data
        }
        LicenseMessage::ErrorAlert(error_alert) => return error_alert.is_valid(),
        _ => {
            return Err(Error::RdpError(RdpError::new(
                RdpErrorKind::InvalidRespond,
                "unexpected license message at the start of the license negotation",
            )))
        }
    };

    let (channel, payload) = mcs.read()?;
    match LicenseMessage::new(payload)? {
        LicenseMessage::PlatformChallenge(platform_challenge) => {
            let platform_challenge_response = ClientPlatformChallenge::new(
                platform_challenge,
                &session_encryption_data,
                client_uuid.into_bytes(),
            )?;
            mcs.write(
                &channel,
                license_response(
                    MessageType::PlatformChallengeResponse,
                    platform_challenge_response.to_bytes()?,
                )?,
            )?;
        }
        LicenseMessage::ErrorAlert(error_alert) => return error_alert.is_valid(),
        _ => {
            return Err(Error::RdpError(RdpError::new(
                RdpErrorKind::InvalidRespond,
                "unexpected license message",
            )))
        }
    }

    let (_channel, payload) = mcs.read()?;
    match LicenseMessage::new(payload)? {
        LicenseMessage::NewLicense(new_license) => {
            // At the moment we're not storing license client-side,
            // so we can just validate data and return
            let _license = License::new(&session_encryption_data, &new_license)?;
        }
        LicenseMessage::ErrorAlert(error_alert) => return error_alert.is_valid(),
        _ => {
            return Err(Error::RdpError(RdpError::new(
                RdpErrorKind::InvalidRespond,
                "unexpected license message",
            )))
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    const CLIENT_RANDOM_BUFFER: [u8; 32] = [
        29, 91, 101, 210, 58, 6, 253, 117, 36, 209, 128, 84, 229, 91, 28, 208, 0, 65, 109, 164,
        235, 10, 22, 69, 183, 184, 158, 209, 128, 157, 122, 187,
    ];
    const SERVER_RANDOM_BUFFER: [u8; 32] = [
        135, 43, 167, 218, 195, 159, 70, 134, 193, 59, 40, 249, 168, 129, 51, 230, 69, 18, 45, 19,
        183, 23, 238, 173, 95, 50, 156, 45, 254, 174, 194, 255,
    ];
    const ENCRYPTED_PREMASTER_SECRET: [u8; 72] = [
        62, 187, 238, 159, 188, 213, 152, 124, 16, 119, 43, 178, 109, 127, 28, 8, 220, 233, 172,
        132, 171, 132, 190, 12, 152, 243, 248, 102, 237, 102, 219, 221, 138, 100, 200, 255, 1, 223,
        23, 145, 121, 223, 164, 9, 221, 186, 171, 182, 80, 28, 207, 0, 78, 51, 90, 129, 249, 53,
        187, 221, 207, 31, 213, 62, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    const PREMASTER_SECRET_BUFFER: [u8; 48] = [
        10, 63, 107, 103, 158, 17, 153, 19, 221, 157, 28, 215, 121, 50, 89, 79, 194, 171, 104, 34,
        180, 124, 248, 187, 66, 180, 163, 60, 208, 90, 236, 216, 4, 98, 137, 236, 151, 108, 126,
        215, 164, 2, 191, 110, 236, 93, 51, 40,
    ];
    const SALTED_HASH_BUFFER: [u8; 16] = [
        121, 64, 28, 102, 24, 136, 13, 198, 158, 252, 57, 55, 222, 122, 4, 93,
    ];
    const MASTER_SECRET_BUFFER: [u8; 48] = [
        121, 64, 28, 102, 24, 136, 13, 198, 158, 252, 57, 55, 222, 122, 4, 93, 193, 218, 164, 59,
        153, 133, 183, 145, 40, 134, 109, 239, 233, 122, 214, 75, 248, 66, 147, 166, 135, 133, 144,
        178, 145, 156, 51, 212, 87, 202, 238, 190,
    ];
    const SESSION_KEY_BLOB: [u8; 48] = [
        116, 192, 213, 13, 126, 75, 71, 132, 142, 4, 227, 137, 9, 236, 124, 46, 180, 3, 198, 101,
        137, 71, 69, 8, 249, 165, 203, 120, 82, 245, 219, 102, 102, 5, 158, 87, 22, 221, 137, 195,
        241, 120, 125, 127, 224, 14, 174, 47,
    ];
    const LICENSE_KEY_BUFFER: [u8; 16] = [
        44, 229, 51, 182, 241, 98, 94, 249, 201, 240, 209, 190, 72, 113, 246, 41,
    ];
    const X509_CERTIFICATE: [u8; 1117] = [
        48, 130, 4, 89, 48, 130, 3, 69, 160, 3, 2, 1, 2, 2, 5, 1, 0, 0, 0, 2, 48, 9, 6, 5, 43, 14,
        3, 2, 29, 5, 0, 48, 17, 49, 15, 48, 13, 6, 3, 85, 4, 3, 19, 6, 66, 101, 99, 107, 101, 114,
        48, 30, 23, 13, 49, 57, 49, 48, 50, 54, 50, 51, 50, 54, 52, 53, 90, 23, 13, 51, 56, 48, 49,
        49, 57, 48, 51, 49, 52, 48, 55, 90, 48, 129, 166, 49, 129, 163, 48, 39, 6, 3, 85, 4, 3, 30,
        32, 0, 110, 0, 99, 0, 97, 0, 99, 0, 110, 0, 95, 0, 105, 0, 112, 0, 95, 0, 116, 0, 99, 0,
        112, 0, 58, 0, 49, 0, 50, 0, 55, 48, 51, 6, 3, 85, 4, 7, 30, 44, 0, 110, 0, 99, 0, 97, 0,
        99, 0, 110, 0, 95, 0, 105, 0, 112, 0, 95, 0, 116, 0, 99, 0, 112, 0, 58, 0, 49, 0, 50, 0,
        55, 0, 46, 0, 48, 0, 46, 0, 48, 0, 46, 0, 49, 48, 67, 6, 3, 85, 4, 5, 30, 60, 0, 49, 0, 66,
        0, 99, 0, 75, 0, 101, 0, 86, 0, 51, 0, 77, 0, 103, 0, 116, 0, 106, 0, 85, 0, 116, 0, 111,
        0, 50, 0, 80, 0, 73, 0, 104, 0, 53, 0, 82, 0, 87, 0, 86, 0, 54, 0, 66, 0, 88, 0, 72, 0,
        119, 0, 61, 0, 13, 0, 10, 48, 88, 48, 9, 6, 5, 43, 14, 3, 2, 15, 5, 0, 3, 75, 0, 48, 72, 2,
        65, 0, 171, 172, 135, 17, 131, 191, 233, 72, 37, 0, 44, 51, 49, 94, 61, 120, 200, 95, 130,
        203, 54, 65, 245, 180, 101, 21, 238, 4, 49, 174, 226, 72, 88, 153, 127, 79, 144, 29, 247,
        124, 215, 248, 71, 147, 160, 202, 156, 223, 145, 176, 65, 232, 5, 75, 220, 36, 91, 114,
        247, 104, 145, 132, 251, 25, 2, 3, 1, 0, 1, 163, 130, 1, 244, 48, 130, 1, 240, 48, 20, 6,
        9, 43, 6, 1, 4, 1, 130, 55, 18, 4, 1, 1, 255, 4, 4, 1, 0, 5, 0, 48, 60, 6, 9, 43, 6, 1, 4,
        1, 130, 55, 18, 2, 1, 1, 255, 4, 44, 77, 0, 105, 0, 99, 0, 114, 0, 111, 0, 115, 0, 111, 0,
        102, 0, 116, 0, 32, 0, 67, 0, 111, 0, 114, 0, 112, 0, 111, 0, 114, 0, 97, 0, 116, 0, 105,
        0, 111, 0, 110, 0, 0, 0, 48, 129, 221, 6, 9, 43, 6, 1, 4, 1, 130, 55, 18, 5, 1, 1, 255, 4,
        129, 204, 0, 48, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 34, 4, 0, 0, 28, 0, 74, 0, 102, 0, 74, 0,
        176, 0, 3, 0, 51, 0, 100, 0, 50, 0, 54, 0, 55, 0, 57, 0, 53, 0, 52, 0, 45, 0, 101, 0, 101,
        0, 98, 0, 55, 0, 45, 0, 49, 0, 49, 0, 100, 0, 49, 0, 45, 0, 98, 0, 57, 0, 52, 0, 101, 0,
        45, 0, 48, 0, 48, 0, 99, 0, 48, 0, 52, 0, 102, 0, 97, 0, 51, 0, 48, 0, 56, 0, 48, 0, 100,
        0, 0, 0, 51, 0, 100, 0, 50, 0, 54, 0, 55, 0, 57, 0, 53, 0, 52, 0, 45, 0, 101, 0, 101, 0,
        98, 0, 55, 0, 45, 0, 49, 0, 49, 0, 100, 0, 49, 0, 45, 0, 98, 0, 57, 0, 52, 0, 101, 0, 45,
        0, 48, 0, 48, 0, 99, 0, 48, 0, 52, 0, 102, 0, 97, 0, 51, 0, 48, 0, 56, 0, 48, 0, 100, 0, 0,
        0, 0, 0, 0, 0, 0, 128, 128, 0, 0, 0, 0, 16, 0, 128, 128, 0, 0, 0, 0, 0, 0, 128, 128, 0, 0,
        0, 0, 0, 48, 129, 128, 6, 9, 43, 6, 1, 4, 1, 130, 55, 18, 6, 1, 1, 255, 4, 112, 0, 48, 0,
        0, 0, 0, 32, 0, 80, 0, 87, 0, 73, 0, 78, 0, 45, 0, 52, 0, 76, 0, 52, 0, 76, 0, 54, 0, 65,
        0, 77, 0, 66, 0, 67, 0, 83, 0, 81, 0, 0, 0, 48, 0, 48, 0, 52, 0, 50, 0, 57, 0, 45, 0, 48,
        0, 48, 0, 48, 0, 48, 0, 48, 0, 45, 0, 51, 0, 52, 0, 57, 0, 55, 0, 50, 0, 45, 0, 65, 0, 84,
        0, 51, 0, 53, 0, 51, 0, 0, 0, 87, 0, 79, 0, 82, 0, 75, 0, 71, 0, 82, 0, 79, 0, 85, 0, 80,
        0, 0, 0, 0, 0, 48, 55, 6, 3, 85, 29, 35, 1, 1, 255, 4, 45, 48, 43, 161, 34, 164, 32, 87, 0,
        73, 0, 78, 0, 45, 0, 52, 0, 76, 0, 52, 0, 76, 0, 54, 0, 65, 0, 77, 0, 66, 0, 67, 0, 83, 0,
        81, 0, 0, 0, 130, 5, 1, 0, 0, 0, 2, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 3, 130, 1, 1, 0,
        62, 211, 213, 97, 138, 135, 123, 152, 44, 109, 32, 56, 18, 8, 216, 247, 131, 8, 248, 230,
        178, 225, 33, 225, 48, 97, 18, 25, 232, 193, 65, 175, 89, 124, 30, 62, 200, 64, 158, 36,
        232, 141, 12, 65, 253, 248, 62, 161, 179, 172, 86, 172, 82, 145, 90, 248, 208, 64, 142, 19,
        71, 169, 138, 10, 98, 109, 17, 137, 32, 86, 231, 214, 95, 18, 68, 148, 191, 99, 153, 163,
        66, 64, 213, 198, 140, 31, 75, 248, 175, 131, 142, 246, 116, 178, 11, 85, 19, 74, 118, 237,
        55, 216, 61, 19, 231, 174, 67, 76, 154, 97, 108, 123, 27, 209, 170, 0, 151, 223, 91, 133,
        159, 200, 238, 108, 229, 162, 99, 118, 228, 6, 211, 42, 224, 85, 225, 146, 120, 237, 3,
        123, 125, 26, 110, 194, 86, 220, 173, 110, 215, 169, 254, 167, 253, 9, 10, 166, 213, 138,
        153, 164, 117, 137, 173, 132, 199, 9, 247, 76, 110, 208, 226, 128, 23, 98, 250, 134, 254,
        67, 81, 242, 180, 246, 239, 59, 179, 61, 31, 239, 163, 203, 162, 87, 37, 124, 2, 242, 39,
        28, 135, 112, 142, 132, 32, 254, 29, 74, 196, 135, 36, 59, 186, 255, 52, 26, 226, 255, 162,
        67, 57, 216, 25, 151, 248, 240, 249, 115, 166, 182, 85, 100, 166, 202, 163, 72, 34, 183,
        26, 155, 152, 26, 142, 47, 170, 236, 193, 254, 37, 54, 43, 112, 151, 140, 91, 98, 33, 195,
    ];

    fn parse_hex_str(s: &str) -> Vec<u8> {
        hex::decode(
            s.lines()
                .map(|l| l.trim_start())
                .filter(|l| !l.is_empty())
                .flat_map(|l| l[10..58].chars())
                .filter(char::is_ascii_hexdigit)
                .collect::<String>(),
        )
        .unwrap()
    }

    #[test]
    fn test_server_license_request() {
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpele/a870d76a-639b-4757-9370-a9bdfbfd6961
        let payload: Vec<u8> = parse_hex_str(
            r#"
            00000000  01 03 98 08 84 ef ae 20-b1 d5 9e 36 49 1a e8 2e   ....... ...6I...
            00000010  0a 99 89 ac 49 a6 47 4f-33 9b 5a b9 95 03 a6 c6   ....I.GO3.Z.....
            00000020  c2 3c 3f 61 00 00 06 00-2c 00 00 00 4d 00 69 00   .<?a....,...M.i.
            00000030  63 00 72 00 6f 00 73 00-6f 00 66 00 74 00 20 00   c.r.o.s.o.f.t. .
            00000040  43 00 6f 00 72 00 70 00-6f 00 72 00 61 00 74 00   C.o.r.p.o.r.a.t.
            00000050  69 00 6f 00 6e 00 00 00-08 00 00 00 41 00 30 00   i.o.n.......A.0.
            00000060  32 00 00 00 0d 00 04 00-01 00 00 00 03 00 12 08   2...............
            00000070  02 00 00 80 02 00 00 00-f5 02 00 00 30 82 02 f1   ............0...
            00000080  30 82 01 dd a0 03 02 01-02 02 08 01 9e 24 a2 f2   0............$..
            00000090  ae 90 80 30 09 06 05 2b-0e 03 02 1d 05 00 30 32   ...0...+......02
            000000A0  31 30 30 13 06 03 55 04-03 1e 0c 00 52 00 4f 00   100...U.....R.O.
            000000B0  44 00 45 00 4e 00 54 30-19 06 03 55 04 07 1e 12   D.E.N.T0...U....
            000000C0  00 57 00 4f 00 52 00 4b-00 47 00 52 00 4f 00 55   .W.O.R.K.G.R.O.U
            000000D0  00 50 30 1e 17 0d 37 30-30 35 32 37 30 31 31 31   .P0...7005270111
            000000E0  30 33 5a 17 0d 34 39 30-35 32 37 30 31 31 31 30   03Z..49052701110
            000000F0  33 5a 30 32 31 30 30 13-06 03 55 04 03 1e 0c 00   3Z02100...U.....
            00000100  52 00 4f 00 44 00 45 00-4e 00 54 30 19 06 03 55   R.O.D.E.N.T0...U
            00000110  04 07 1e 12 00 57 00 4f-00 52 00 4b 00 47 00 52   .....W.O.R.K.G.R
            00000120  00 4f 00 55 00 50 30 82-01 22 30 0d 06 09 2a 86   .O.U.P0.."0...*.
            00000130  48 86 f7 0d 01 01 01 05-00 03 82 01 0f 00 30 82   H.............0.
            00000140  01 0a 02 82 01 01 00 88-ad 7c 8f 8b 82 76 5a bd   .........|...vZ.
            00000150  8f 6f 62 18 e1 d9 aa 41-fd ed 68 01 c6 34 35 b0   .ob....A..h..45.
            00000160  29 04 ca 4a 4a 1c 7e 80-14 f7 8e 77 b8 25 ff 16   )..JJ.~....w.%..
            00000170  47 6f bd e2 34 3d 2e 02-b9 53 e4 33 75 ad 73 28   Go..4=...S.3u.s(
            00000180  80 a0 4d fc 6c c0 22 53-1b 2c f8 f5 01 60 19 7e   ..M.l."S.,...`.~
            00000190  79 19 39 8d b5 ce 39 58-dd 55 24 3b 55 7b 43 c1   y.9...9X.U$;U{C.
            000001A0  7f 14 2f b0 64 3a 54 95-2b 88 49 0c 61 2d ac f8   ../.d:T.+.I.a-..
            000001B0  45 f5 da 88 18 5f ae 42-f8 75 c7 26 6d b5 bb 39   E...._.B.u.&m..9
            000001C0  6f cc 55 1b 32 11 38 8d-e4 e9 44 84 11 36 a2 61   o.U.2.8...D..6.a
            000001D0  76 aa 4c b4 e3 55 0f e4-77 8e de e3 a9 ea b7 41   v.L..U..w......A
            000001E0  94 00 58 aa c9 34 a2 98-c6 01 1a 76 14 01 a8 dc   ..X..4.....v....
            000001F0  30 7c 77 5a 20 71 5a a2-3f af 13 7e e8 fd 84 a2   0|wZ qZ.?..~....
            00000200  5b cf 25 e9 c7 8f a8 f2-8b 84 c7 04 5e 53 73 4e   [.%.........^SsN
            00000210  0e 89 a3 3c e7 68 5c 24-b7 80 53 3c 54 c8 c1 53   ...<.h\$..S<T..S
            00000220  aa 71 71 3d 36 15 d6 6a-9d 7d de ae f9 e6 af 57   .qq=6..j.}.....W
            00000230  ae b9 01 96 5d e0 4d cd-ed c8 d7 f3 01 03 38 10   ....].M.......8.
            00000240  be 7c 42 67 01 a7 23 02-03 01 00 01 a3 13 30 11   .|Bg..#.......0.
            00000250  30 0f 06 03 55 1d 13 04-08 30 06 01 01 ff 02 01   0...U....0......
            00000260  00 30 09 06 05 2b 0e 03-02 1d 05 00 03 82 01 01   .0...+..........
            00000270  00 81 dd d2 d3 33 d4 a3-b6 8e 6e 7d 9f fd 73 9f   .....3....n}..s.
            00000280  31 0b dd 42 82 3f 7e 21-df 28 cc 59 ca 6a c0 a9   1..B.?~!.(.Y.j..
            00000290  3d 30 7d e1 91 db 77 6b-8b 10 e6 fd bc 3c a3 58   =0}...wk.....<.X
            000002A0  48 c2 36 dd a0 0b f5 8e-13 da 7b 04 08 44 b4 f2   H.6.......{..D..
            000002B0  a8 0d 1e 0b 1d 1a 3f f9-9b 4b 5a 54 c5 b3 b4 03   ......?..KZT....
            000002C0  93 75 b3 72 5c 3d cf 63-0f 15 e1 64 58 de 52 8d   .u.r\=.c...dX.R.
            000002D0  97 79 0e a4 34 d5 66 05-58 b8 6e 79 b2 09 86 d5   .y..4.f.X.ny....
            000002E0  f0 ed c4 6b 4c ab 02 b8-16 5f 3b ed 88 5f d1 de   ...kL...._;.._..
            000002F0  44 e3 73 47 21 f7 03 ce-e1 6d 10 0f 95 cf 7c a2   D.sG!....m....|.
            00000300  7a a6 bf 20 db e1 93 04-c8 5e 6a be c8 01 5d 27   z.. .....^j...]'
            00000310  b2 03 0f 66 75 e7 cb ea-8d 4e 98 9d 22 ed 28 40   ...fu....N..".(@
            00000320  d2 7d a4 4b ef cc bf 01-2a 6d 3a 3e be 47 38 f8   .}.K....*m:>.G8.
            00000330  ea a4 c6 30 1d 5e 25 cf-fb e8 3d 42 dd 29 e8 99   ...0.^%...=B.)..
            00000340  89 9e bf 39 ee 77 09 d9-3e 8b 52 36 b6 bb 8b bd   ...9.w..>.R6....
            00000350  0d b2 52 aa 2c cf 38 4e-4d cf 1d 6d 5d 25 17 ac   ..R.,.8NM..m]%..
            00000360  2c f6 f0 65 5a c9 fe 31-53 b4 f0 0c 94 4e 0d 54   ,..eZ..1S....N.T
            00000370  8e fd 04 00 00 30 82 04-f9 30 82 03 e5 a0 03 02   .....0...0......
            00000380  01 02 02 05 01 00 00 00-02 30 09 06 05 2b 0e 03   .........0...+..
            00000390  02 1d 05 00 30 32 31 30-30 13 06 03 55 04 03 1e   ....02100...U...
            000003A0  0c 00 52 00 4f 00 44 00-45 00 4e 00 54 30 19 06   ..R.O.D.E.N.T0..
            000003B0  03 55 04 07 1e 12 00 57-00 4f 00 52 00 4b 00 47   .U.....W.O.R.K.G
            000003C0  00 52 00 4f 00 55 00 50-30 1e 17 0d 30 37 30 35   .R.O.U.P0...0705
            000003D0  32 36 31 32 34 35 35 33-5a 17 0d 33 38 30 31 31   26124553Z..38011
            000003E0  39 30 33 31 34 30 37 5a-30 81 92 31 81 8f 30 23   9031407Z0..1..0#
            000003F0  06 03 55 04 03 1e 1c 00-6e 00 63 00 61 00 6c 00   ..U.....n.c.a.l.
            00000400  72 00 70 00 63 00 3a 00-52 00 4f 00 44 00 45 00   r.p.c.:.R.O.D.E.
            00000410  4e 00 54 30 23 06 03 55-04 07 1e 1c 00 6e 00 63   N.T0#..U.....n.c
            00000420  00 61 00 6c 00 72 00 70-00 63 00 3a 00 52 00 4f   .a.l.r.p.c.:.R.O
            00000430  00 44 00 45 00 4e 00 54-30 43 06 03 55 04 05 1e   .D.E.N.T0C..U...
            00000440  3c 00 31 00 42 00 63 00-4b 00 65 00 62 00 68 00   <.1.B.c.K.e.b.h.
            00000450  70 00 58 00 5a 00 74 00-4c 00 71 00 4f 00 37 00   p.X.Z.t.L.q.O.7.
            00000460  53 00 51 00 6e 00 42 00-70 00 52 00 66 00 75 00   S.Q.n.B.p.R.f.u.
            00000470  64 00 64 00 64 00 59 00-3d 00 0d 00 0a 30 82 01   d.d.d.Y.=....0..
            00000480  1e 30 09 06 05 2b 0e 03-02 0f 05 00 03 82 01 0f   .0...+..........
            00000490  00 30 82 01 0a 02 82 01-01 00 c8 90 6b f0 c6 58   .0..........k..X
            000004A0  81 a6 89 1c 0e f2 f6 d9-82 12 71 a5 6e 51 db e0   ..........q.nQ..
            000004B0  32 66 aa 91 77 0e 88 ab-44 b7 d3 97 da 78 8f 0e   2f..w...D....x..
            000004C0  44 26 46 7f 16 d4 c6 63-eb ca 55 e5 4e 8b 2d a6   D&F....c..U.N.-.
            000004D0  6d 83 95 a7 a8 6a fa d0-be 26 80 ae ab 0a 64 90   m....j...&....d.
            000004E0  32 8c df 5c f8 f9 d0 7e-d1 6b 3a 29 7e 7d bd 02   2..\...~.k:)~}..
            000004F0  a3 86 6c fd a5 35 71 da-21 b4 ee a4 97 f3 a8 b2   ..l..5q.!.......
            00000500  12 db a4 27 57 36 c9 08-22 5c 54 f7 99 7b a3 2f   ...'W6.."\T..{./
            00000510  b8 5c d5 16 b8 19 27 6b-71 97 14 5b e8 1f 23 e8   .\....'kq..[..#.
            00000520  5c b8 1b 73 4b 6e 7a 03-13 ff 97 e9 62 b9 4a a0   \..sKnz.....b.J.
            00000530  51 23 c3 6c 32 3e 02 f2-63 97 23 1c c5 78 d8 fc   Q#.l2>..c.#..x..
            00000540  b7 07 4b b0 56 0f 74 df-c5 56 28 e4 96 fd 20 8e   ..K.V.t..V(... .
            00000550  65 5a e6 45 ed c1 05 3e-ab 58 55 40 af e2 47 a0   eZ.E...>.XU@..G.
            00000560  4c 49 a3 8d 39 e3 66 5f-93 33 6d f8 5f c5 54 e5   LI..9.f_.3m._.T.
            00000570  fb 57 3a de 45 12 b5 c7-05 4b 88 1f b4 35 0f 7c   .W:.E....K...5.|
            00000580  c0 75 17 c6 67 dd 48 80-cb 0a be 9d f6 93 60 65   .u..g.H.......`e
            00000590  34 eb 97 af 65 6d df bf-6f 5b 02 03 01 00 01 a3   4...em..o[......
            000005A0  82 01 bf 30 82 01 bb 30-14 06 09 2b 06 01 04 01   ...0...0...+....
            000005B0  82 37 12 04 01 01 ff 04-04 01 00 05 00 30 3c 06   .7...........0<.
            000005C0  09 2b 06 01 04 01 82 37-12 02 01 01 ff 04 2c 4d   .+.....7......,M
            000005D0  00 69 00 63 00 72 00 6f-00 73 00 6f 00 66 00 74   .i.c.r.o.s.o.f.t
            000005E0  00 20 00 43 00 6f 00 72-00 70 00 6f 00 72 00 61   . .C.o.r.p.o.r.a
            000005F0  00 74 00 69 00 6f 00 6e-00 00 00 30 81 cd 06 09   .t.i.o.n...0....
            00000600  2b 06 01 04 01 82 37 12-05 01 01 ff 04 81 bc 00   +.....7.........
            00000610  30 00 00 01 00 00 00 02-00 00 00 09 04 00 00 1c   0...............
            00000620  00 4a 00 66 00 4a 00 b0-00 01 00 33 00 64 00 32   .J.f.J.....3.d.2
            00000630  00 36 00 37 00 39 00 35-00 34 00 2d 00 65 00 65   .6.7.9.5.4.-.e.e
            00000640  00 62 00 37 00 2d 00 31-00 31 00 64 00 31 00 2d   .b.7.-.1.1.d.1.-
            00000650  00 62 00 39 00 34 00 65-00 2d 00 30 00 30 00 63   .b.9.4.e.-.0.0.c
            00000660  00 30 00 34 00 66 00 61-00 33 00 30 00 38 00 30   .0.4.f.a.3.0.8.0
            00000670  00 64 00 00 00 33 00 64-00 32 00 36 00 37 00 39   .d...3.d.2.6.7.9
            00000680  00 35 00 34 00 2d 00 65-00 65 00 62 00 37 00 2d   .5.4.-.e.e.b.7.-
            00000690  00 31 00 31 00 64 00 31-00 2d 00 62 00 39 00 34   .1.1.d.1.-.b.9.4
            000006A0  00 65 00 2d 00 30 00 30-00 63 00 30 00 34 00 66   .e.-.0.0.c.0.4.f
            000006B0  00 61 00 33 00 30 00 38-00 30 00 64 00 00 00 00   .a.3.0.8.0.d....
            000006C0  00 00 10 00 80 64 00 00-00 00 00 30 6e 06 09 2b   .....d.....0n..+
            000006D0  06 01 04 01 82 37 12 06-01 01 ff 04 5e 00 30 00   .....7......^.0.
            000006E0  00 00 00 0e 00 3e 00 52-00 4f 00 44 00 45 00 4e   .....>.R.O.D.E.N
            000006F0  00 54 00 00 00 37 00 38-00 34 00 34 00 30 00 2d   .T...7.8.4.4.0.-
            00000700  00 30 00 30 00 36 00 2d-00 35 00 38 00 36 00 37   .0.0.6.-.5.8.6.7
            00000710  00 30 00 34 00 35 00 2d-00 37 00 30 00 33 00 34   .0.4.5.-.7.0.3.4
            00000720  00 37 00 00 00 57 00 4f-00 52 00 4b 00 47 00 52   .7...W.O.R.K.G.R
            00000730  00 4f 00 55 00 50 00 00-00 00 00 30 25 06 03 55   .O.U.P.....0%..U
            00000740  1d 23 01 01 ff 04 1b 30-19 a1 10 a4 0e 52 00 4f   .#.....0.....R.O
            00000750  00 44 00 45 00 4e 00 54-00 00 00 82 05 01 00 00   .D.E.N.T........
            00000760  00 02 30 09 06 05 2b 0e-03 02 1d 05 00 03 82 01   ..0...+.........
            00000770  01 00 2e eb c7 0d b8 1d-47 11 9d 09 88 9b 51 dc   ........G.....Q.
            00000780  45 dd 56 51 e2 d1 23 11-39 9b 2d da c7 fe 7a d7   E.VQ..#.9.-...z.
            00000790  84 e3 3d 54 77 97 4d 19-92 30 64 a0 47 c6 2f 6d   ..=Tw.M..0d.G./m
            000007A0  93 d2 64 7c 76 c8 26 45-ad 5a 44 54 ea f6 4b 28   ..d|v.&E.ZDT..K(
            000007B0  77 1f 77 ea ec 74 02 38-68 9e 79 14 72 83 34 74   w.w..t.8h.y.r.4t
            000007C0  62 d2 c1 0c a4 0b f2 a9-b0 38 bb 7c d0 ae be bf   b........8.|....
            000007D0  74 47 16 a0 a2 d3 fc 1d-b9 ba 26 10 06 ef ba 1d   tG........&.....
            000007E0  43 01 4e 4e 6f 56 ca e0-ee d0 f9 4e a6 62 63 ff   C.NNoV.....N.bc.
            000007F0  da 0b c9 15 61 6c ed 6b-0b c4 58 53 86 0f 8c 0c   ....al.k..XS....
            00000800  1a 2e df c1 f2 43 48 d4-af 0a 78 36 b2 51 32 28   .....CH...x6.Q2(
            00000810  6c c2 75 79 3f 6e 99 66-88 3e 34 d3 7f 6d 9d 07   l.uy?n.f.>4..m..
            00000820  e4 6b eb 84 e2 0a bb ca-7d 3a 40 71 b0 be 47 9f   .k......}:@q..G.
            00000830  12 58 31 61 2b 9b 4a 9a-49 8f e5 b4 0c f5 04 4d   .X1a+.J.I......M
            00000840  3c ce bc d2 79 15 d9 28-f4 23 56 77 9f 38 64 3e   <...y..(.#Vw.8d>
            00000850  03 88 92 04 26 76 b9 b5-df 19 d0 78 4b 7a 60 40   ....&v.....xKz`@
            00000860  23 91 f1 15 22 2b b4 e7-02 54 a9 16 21 5b 60 96   #..."+...T..![`.
            00000870  a9 5c 00 00 00 00 00 00-00 00 00 00 00 00 00 00   .\..............
            00000880  00 00 01 00 00 00 0e 00-0e 00 6d 69 63 72 6f 73   ..........micros
            00000890  6f 66 74 2e 63 6f 6d 00                           oft.com.
            "#,
        );

        // trim the licensing preamble (first 4 bytes)
        let server_license_request =
            ServerLicenseRequest::from_bytes(&mut Cursor::new(&payload[4..])).unwrap();
        assert_eq!(
            server_license_request.server_random,
            vec![
                0x84, 0xef, 0xae, 0x20, 0xb1, 0xd5, 0x9e, 0x36, 0x49, 0x1a, 0xe8, 0x2e, 0x0a, 0x99,
                0x89, 0xac, 0x49, 0xa6, 0x47, 0x4f, 0x33, 0x9b, 0x5a, 0xb9, 0x95, 0x03, 0xa6, 0xc6,
                0xc2, 0x3c, 0x3f, 0x61,
            ]
        );
        assert_eq!(server_license_request.version_major, 6);
        assert_eq!(server_license_request.version_minor, 0);
        assert_eq!(
            server_license_request.company_name,
            String::from("Microsoft Corporation")
        );
        assert_eq!(server_license_request.product_id, String::from("A02"));
    }

    #[test]
    fn test_generate_salted_hash() {
        let result = SessionEncryptionData::salted_hash(
            b"A",
            PREMASTER_SECRET_BUFFER.as_ref(),
            CLIENT_RANDOM_BUFFER.as_ref(),
            SERVER_RANDOM_BUFFER.as_ref(),
        );
        assert_eq!(result, SALTED_HASH_BUFFER.as_ref());
    }

    #[test]
    fn test_generate_master_secret() {
        let result = SessionEncryptionData::master_secret(
            PREMASTER_SECRET_BUFFER.as_ref(),
            CLIENT_RANDOM_BUFFER.as_ref(),
            SERVER_RANDOM_BUFFER.as_ref(),
        );
        assert_eq!(result, MASTER_SECRET_BUFFER.as_ref());
    }

    #[test]
    fn test_generate_session_key() {
        let result = SessionEncryptionData::session_key_blob(
            MASTER_SECRET_BUFFER.as_ref(),
            CLIENT_RANDOM_BUFFER.as_ref(),
            SERVER_RANDOM_BUFFER.as_ref(),
        );
        assert_eq!(result, SESSION_KEY_BLOB.as_ref());
    }

    #[test]
    fn test_generate_session_encryption_data() {
        let session_encryption = SessionEncryptionData::new(
            CLIENT_RANDOM_BUFFER.to_vec(),
            SERVER_RANDOM_BUFFER.to_vec(),
            PREMASTER_SECRET_BUFFER.to_vec(),
            ServerCertificate::from_der(&X509_CERTIFICATE).unwrap(),
        );
        assert_eq!(
            session_encryption.license_encryption_key,
            LICENSE_KEY_BUFFER.as_ref(),
        );

        let encrypted = session_encryption
            .encrypt_message(PREMASTER_SECRET_BUFFER.as_ref())
            .unwrap();
        assert_eq!(encrypted, ENCRYPTED_PREMASTER_SECRET.as_ref());
    }
}
