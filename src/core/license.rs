use core::mcs;
use core::tpkt;
use model::data::{Check, Component, DataType, DynOption, Message, MessageOption, Trame, U16, U32};
use model::error::{Error, RdpError, RdpErrorKind, RdpResult};
use model::rnd::random;
use num_enum::TryFromPrimitive;
use std::convert::{TryFrom, TryInto};
use std::ffi::CString;
use std::io::{self, Cursor, Read, Write};

use core::sec::SecurityFlag;

use md5::Digest;
use num_bigint::BigUint;
use rc4::{Key, Rc4};
use rc4::{KeyInit, StreamCipher};
use ring::digest;
use rsa::{PublicKeyParts, RsaPublicKey};
use x509_parser::{certificate::X509Certificate, prelude::*};

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
#[derive(TryFromPrimitive)]
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
                &format!("Licensing nego not implemented. bMsgtype: {:?}", msg_type),
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
                            "unsupported signature or key algorithm, dwSigAlgId={} dwKeyAlgId={}",
                            sig_alg_id, key_alg_id
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
                        &format!("invalid number of certificates in the chain. expected minimum 2, found: {}", num_cert_blobs),
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

pub struct ServerLicenseRequest {
    server_random: Vec<u8>,
    certificate: ServerCertificate,
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
        let server_certificate = cast!(DataType::Component, message["ServerCertificate"])?;
        let mut blob_data = cast!(DataType::Slice, server_certificate["blobData"])?;

        Ok(Self {
            server_random: Vec::from(server_random),
            certificate: ServerCertificate::from_bytes(&mut blob_data)?,
        })
    }
}

struct ClientNewLicense<'a> {
    session_encryption_data: &'a SessionEncryptionData,
    domain: CString,
    username: CString,
}

impl<'a> ClientNewLicense<'a> {
    fn new(
        session_encryption_data: &'a SessionEncryptionData,
        username: CString,
        domain: CString,
    ) -> RdpResult<Self> {
        Ok(Self {
            session_encryption_data,
            username,
            domain,
        })
    }

    fn to_bytes(&self) -> RdpResult<Vec<u8>> {
        let client_new_license_request = component![
            "PreferredKeyExchangeAlg" => U32::LE(KEY_EXCHANGE_ALG_RSA),
            "PlatformId" => U32::LE(ClientOsId::WinNtPost52 as u32 | ClientImageId::Microsoft as u32),
            "ClientRandom" => self.session_encryption_data.client_random.clone(),
            "EncryptedPreMasterSecret" => BinaryBlob::new(BlobType::Random, self.session_encryption_data.encrypt_message(&self.session_encryption_data.premaster_secret)?).component(),
            "ClientUserName" => BinaryBlob::new(BlobType::ClientUserName, self.username.to_bytes_with_nul().to_owned()).component(),
            "ClientMachineName" => BinaryBlob::new(BlobType::ClientMachineName, self.domain.to_bytes_with_nul().to_owned()).component()
        ];

        let mut buf: Vec<u8> = Vec::with_capacity(client_new_license_request.length() as usize);
        client_new_license_request.write(&mut buf)?;
        Ok(buf)
    }
}

struct ClientPlatformChallenge<'a> {
    session_encryption_data: &'a SessionEncryptionData,
    platform_challenge_data: Vec<u8>,
}

impl<'a> ClientPlatformChallenge<'a> {
    fn new(
        platform_challenge: PlatformChallenge,
        session_encryption_data: &'a SessionEncryptionData,
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

        let mut md5 = md5::Md5::new();
        md5.input(gethostname::gethostname().to_str().unwrap_or("default"));
        let hardware_data: [u8; 16] = md5.result().to_vec().try_into().unwrap_or_default();

        let client_hardware_identification = component![
            "PlatformId" => U32::LE(ClientOsId::WinNtPost52 as u32 | ClientImageId::Microsoft as u32),
            "client_hardware_id" => hardware_data.to_vec()
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
            &[
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
            &[
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

/// Wraps license message with security and preamble headers
fn license_response(message_type: MessageType, data: Vec<u8>) -> RdpResult<Vec<u8>> {
    let message = trame![
        U16::LE(SecurityFlag::SecLicensePkt as u16),
        U16::LE(0),
        component![
            "bMsgtype" => message_type as u8,
            "flag" => Check::new(Preambule::PreambleVersion30 as u8),
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
    domain: &str,
    username: &str,
) -> RdpResult<()> {
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
                CString::new(domain).unwrap_or_else(|_| CString::new(".").unwrap()),
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
            let platform_challenge_response =
                ClientPlatformChallenge::new(platform_challenge, &session_encryption_data)?;
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

    #[test]
    fn test_generate_salted_hash() {
        let result = SessionEncryptionData::salted_hash(
            b"A",
            &PREMASTER_SECRET_BUFFER.as_ref(),
            &CLIENT_RANDOM_BUFFER.as_ref(),
            &SERVER_RANDOM_BUFFER.as_ref(),
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
            .encrypt_message(&PREMASTER_SECRET_BUFFER.to_vec())
            .unwrap();
        assert_eq!(encrypted, ENCRYPTED_PREMASTER_SECRET.as_ref());
    }
}
