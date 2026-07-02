mod hello;

pub use hello::build_client_hello;

/// True if the TCP payload starts with a TLS 1.x ClientHello record.
/// Cheap signature check: TLS record type 0x16 (Handshake) + handshake type 0x01 (ClientHello).
pub fn is_client_hello(payload: &[u8]) -> bool {
    payload.len() >= 6 && payload[0] == 0x16 && payload[5] == 0x01
}

/// True if the TCP payload starts with any TLS record type the server emits
/// during/after a successful handshake (ChangeCipherSpec, Alert, Handshake, ApplicationData).
pub fn is_server_response(payload: &[u8]) -> bool {
    payload.len() >= 5 && matches!(payload[0], 0x14..=0x17)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsContentType {
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
    Other(u8),
}

impl TlsContentType {
    fn from_u8(v: u8) -> Self {
        match v {
            20 => TlsContentType::ChangeCipherSpec,
            21 => TlsContentType::Alert,
            22 => TlsContentType::Handshake,
            23 => TlsContentType::ApplicationData,
            other => TlsContentType::Other(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsVersion {
    pub major: u8,
    pub minor: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsFragment {
    ClientHello { sni: Option<String> },
    ServerHello,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsRecord {
    pub content_type: TlsContentType,
    pub version: TlsVersion,
    pub fragment: TlsFragment,
}

/// Greedy SNI extraction from a potentially truncated TLS ClientHello.
/// Works like TSPU/DPI: grabs SNI from whatever bytes are available
/// in the first TCP segment, doesn't need the full TLS record.
pub fn extract_sni(data: &[u8]) -> Option<String> {
    // TLS record header: content_type(1) + version(2) + length(2) = 5 bytes
    // Handshake type at byte 5 must be 0x01 (ClientHello)
    if data.len() < 6 || data[0] != 0x16 || data[5] != 0x01 {
        return None;
    }
    // Use whatever bytes we have after the 5-byte TLS record header
    let body = &data[5..];
    match TlsRecord::parse_client_hello(body) {
        TlsFragment::ClientHello { sni } => sni,
        _ => None,
    }
}

/// Byte range `(offset, len)` of the SNI hostname within the ClientHello payload.
/// The offset is relative to `hello` (the raw TCP payload). Locates the hostname by
/// the extracted SNI string — cheap and parser-independent.
pub fn sni_span(hello: &[u8]) -> Option<(usize, usize)> {
    let sni = extract_sni(hello)?;
    let needle = sni.as_bytes();
    hello
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|offset| (offset, needle.len()))
}

impl TlsRecord {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 5 {
            return None;
        }

        let content_type = TlsContentType::from_u8(data[0]);
        let version = TlsVersion {
            major: data[1],
            minor: data[2],
        };
        let length = u16::from_be_bytes([data[3], data[4]]) as usize;

        if data.len() < 5 + length {
            return None;
        }

        let body = &data[5..5 + length];

        let fragment = match content_type {
            TlsContentType::Handshake => Self::parse_handshake(body),
            _ => TlsFragment::Other,
        };

        Some(TlsRecord {
            content_type,
            version,
            fragment,
        })
    }

    fn parse_handshake(data: &[u8]) -> TlsFragment {
        if data.is_empty() {
            return TlsFragment::Other;
        }

        match data[0] {
            1 => Self::parse_client_hello(data),
            2 => TlsFragment::ServerHello,
            _ => TlsFragment::Other,
        }
    }

    pub(crate) fn parse_client_hello(data: &[u8]) -> TlsFragment {
        // handshake_type(1) + length(3) + client_version(2) + random(32) = 38 min
        if data.len() < 38 {
            return TlsFragment::ClientHello { sni: None };
        }

        let mut pos = 38;

        // session_id
        if pos >= data.len() {
            return TlsFragment::ClientHello { sni: None };
        }
        let session_id_len = data[pos] as usize;
        pos += 1 + session_id_len;

        // cipher_suites
        if pos + 2 > data.len() {
            return TlsFragment::ClientHello { sni: None };
        }
        let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2 + cipher_suites_len;

        // compression_methods
        if pos >= data.len() {
            return TlsFragment::ClientHello { sni: None };
        }
        let comp_methods_len = data[pos] as usize;
        pos += 1 + comp_methods_len;

        // extensions
        if pos + 2 > data.len() {
            return TlsFragment::ClientHello { sni: None };
        }
        let extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        let extensions_end = (pos + extensions_len).min(data.len());
        let sni = Self::find_sni(&data[pos..extensions_end]);

        TlsFragment::ClientHello { sni }
    }

    fn find_sni(extensions: &[u8]) -> Option<String> {
        let mut pos = 0;
        while pos + 4 <= extensions.len() {
            let ext_type = u16::from_be_bytes([extensions[pos], extensions[pos + 1]]);
            let ext_len = u16::from_be_bytes([extensions[pos + 2], extensions[pos + 3]]) as usize;
            pos += 4;

            if ext_type == 0x0000 && ext_len >= 5 && pos + ext_len <= extensions.len() {
                let sni_data = &extensions[pos..pos + ext_len];
                if sni_data.len() >= 5 {
                    let name_type = sni_data[2];
                    let name_len = u16::from_be_bytes([sni_data[3], sni_data[4]]) as usize;
                    if name_type == 0 && 5 + name_len <= sni_data.len() {
                        return String::from_utf8(sni_data[5..5 + name_len].to_vec()).ok();
                    }
                }
            }

            pos += ext_len;
        }
        None
    }
}
