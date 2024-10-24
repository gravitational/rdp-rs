use crate::core::license;
use crate::core::mcs;
use crate::model::data::{Component, Trame, U16, U32};
use crate::model::error::RdpResult;
use crate::model::unicode::Unicode;
use std::io::{Read, Write};

use super::LicenseStore;

/// Security flag send as header flage in core ptotocol
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/e13405c5-668b-4716-94b2-1c2654ca1ad4?redirectedfrom=MSDN
#[repr(u16)]
#[allow(dead_code)]
pub enum SecurityFlag {
    SecExchangePkt = 0x0001,
    SecTransportReq = 0x0002,
    RdpSecTransportRsp = 0x0004,
    SecEncrypt = 0x0008,
    SecResetSeqno = 0x0010,
    SecIgnoreSeqno = 0x0020,
    SecInfoPkt = 0x0040,
    SecLicensePkt = 0x0080,
    SecLicenseEncryptCs = 0x0200,
    SecRedirectionPkt = 0x0400,
    SecSecureChecksum = 0x0800,
    SecAutodetectReq = 0x1000,
    SecAutodetectRsp = 0x2000,
    SecHeartbeat = 0x4000,
    SecFlagshiValid = 0x8000,
}

/// RDP option someone links to capabilities
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/732394f5-e2b5-4ac5-8a0a-35345386b0d1?redirectedfrom=MSDN
pub enum InfoFlag {
    InfoMouse = 0x00000001,
    InfoDisablectrlaltdel = 0x00000002,
    InfoAutologon = 0x00000008,
    InfoUnicode = 0x00000010,
    InfoMaximizeshell = 0x00000020,
    InfoLogonnotify = 0x00000040,
    InfoCompression = 0x00000080,
    InfoEnablewindowskey = 0x00000100,
    InfoRemoteconsoleaudio = 0x00002000,
    InfoForceEncryptedCsPdu = 0x00004000,
    InfoRail = 0x00008000,
    InfoLogonerrors = 0x00010000,
    InfoMouseHasWheel = 0x00020000,
    InfoPasswordIsScPin = 0x00040000,
    InfoNoaudioplayback = 0x00080000,
    InfoUsingSavedCreds = 0x00100000,
    InfoAudiocapture = 0x00200000,
    InfoVideoDisable = 0x00400000,
    InfoCompressionTypeMask = 0x00001E00,
}

/// Optional performance flags as specified in
/// 2.2.1.11.1.1.1 (TS_EXTENDED_INFO_PACKET)
pub enum ExtendedInfoFlag {
    PerfDisableWallpaper = 0x00000001,
    PerfDisableFullWindowDrag = 0x00000002,
    PerfDisableMenuAnimations = 0x00000004,
    PerfDisableTheming = 0x00000008,
    PerfDisableCursorShadow = 0x00000020,
    PerfDisableCursorBlink = 0x00000040,
    PerfEnableFontSmoothing = 0x00000080,
    PerfEnableDesktopComposition = 0x00000100,
}

#[allow(dead_code)]
enum AfInet {
    AfInet = 0x00002,
    AfInet6 = 0x0017,
}

/// On RDP version > 5
/// Client have to send IP information
///
/// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/05ada9e4-a468-494b-8694-eb806a0ecc89
fn rdp_extended_infos(performance_flags: u32) -> Component {
    component![
        "clientAddressFamily" => U16::LE(AfInet::AfInet as u16),
        "cbClientAddress" => U16::LE(2), // size in bytes of the hardcoded null terminator in clientAddress
        "clientAddress" => b"\x00\x00".to_vec(),
        "cbClientDir" => U16::LE(2), // size in bytes of the hardcoded null terminator in clientDir
        "clientDir" => b"\x00\x00".to_vec(),
        "clientTimeZone" => vec![0; 172],
        "clientSessionId" => U32::LE(0),
        "performanceFlags" => U32::LE(performance_flags)
    ]
}

/// When CSSP is not used
/// interactive logon used credentials
/// present in this payload
fn rdp_infos(
    domain: &String,
    username: &String,
    password: &String,
    auto_logon: bool,
    info_flags: Option<u32>,
    extended_info_flags: Option<u32>,
) -> Component {
    let mut domain_format = domain.to_unicode();
    domain_format.push(0);
    domain_format.push(0);

    let mut username_format = username.to_unicode();
    username_format.push(0);
    username_format.push(0);

    let mut password_format = password.to_unicode();
    password_format.push(0);
    password_format.push(0);

    component![
        "codePage" => U32::LE(0),
        "flag" => U32::LE(
            info_flags.unwrap_or(0) |
            InfoFlag::InfoMouse as u32 |
            InfoFlag::InfoMouseHasWheel as u32 |
            InfoFlag::InfoUnicode as u32 |
            InfoFlag::InfoDisablectrlaltdel as u32 |
            InfoFlag::InfoEnablewindowskey as u32 |
            if auto_logon { InfoFlag::InfoAutologon as u32 } else { 0 }
        ),
        "cbDomain" => U16::LE((domain_format.len() - 2) as u16),
        "cbUserName" => U16::LE((username_format.len() - 2) as u16),
        "cbPassword" => U16::LE((password_format.len() - 2) as u16),
        "cbAlternateShell" => U16::LE(0),
        "cbWorkingDir" => U16::LE(0),
        "domain" => domain_format,
        "userName" => username_format,
        "password" => password_format,
        "alternateShell" => b"\x00\x00".to_vec(),
        "workingDir" => b"\x00\x00".to_vec(),
        "extendedInfos" => match extended_info_flags {
            Some(f) => rdp_extended_infos(f),
            None => component![]
        }
    ]
}

/// Security layer need mcs layer and send all message through
/// the global channel
///
/// This function is called sec because old RDP security
/// was made here
///
/// # Example
/// ```rust, ignore
/// use rdp::core::sec;
/// let mut mcs = mcs::Client(...).unwrap();
/// sec::connect(&mut mcs).unwrap();
/// ```
#[allow(clippy::too_many_arguments)]
pub fn connect<T: Read + Write, L: LicenseStore>(
    mcs: &mut mcs::Client<T>,
    agent_id: &str,
    domain: &String,
    username: &String,
    password: &String,
    auto_logon: bool,
    info_flags: Option<u32>,
    extended_info_flags: Option<u32>,
    license_store: L,
) -> RdpResult<()> {
    let perf_flags = if mcs.is_rdp_version_5_plus() {
        extended_info_flags
    } else {
        None
    };
    // Client Info PDU
    mcs.write(
        &"global".to_string(),
        trame![
            U16::LE(SecurityFlag::SecInfoPkt as u16),
            U16::LE(0),
            rdp_infos(domain, username, password, auto_logon, info_flags, perf_flags)
        ],
    )?;

    license::client_connect(mcs, agent_id, username, license_store)?;
    Ok(())
}
