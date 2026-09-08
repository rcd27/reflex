pub mod cache;

pub use cache::DnsCache;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsDirection {
    Query,
    Response,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    pub id: u16,
    pub direction: DnsDirection,
    /// Код ответа (`RCODE`): 0 — есть ответ, 3 — имени не существует.
    ///
    /// Без него «имя не существует» и «адрес вырезали из ответа» неразличимы, а лечение у них
    /// противоположное: первое — норма поиска по суффиксам, второе — работа цензора.
    pub rcode: u8,
    pub queries: Vec<DnsQuery>,
    pub answers: Vec<DnsAnswer>,
}

const DNS_HEADER_LEN: usize = 12;

impl DnsMessage {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < DNS_HEADER_LEN {
            return None;
        }

        let id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let direction = if flags & 0x8000 != 0 {
            DnsDirection::Response
        } else {
            DnsDirection::Query
        };
        let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
        let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

        let mut pos = DNS_HEADER_LEN;

        let mut queries = Vec::with_capacity(qdcount);
        for _ in 0..qdcount {
            let (name, new_pos) = Self::read_name(data, pos)?;
            pos = new_pos;
            if pos + 4 > data.len() {
                return None;
            }
            let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let qclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
            pos += 4;
            queries.push(DnsQuery {
                name,
                qtype,
                qclass,
            });
        }

        let mut answers = Vec::with_capacity(ancount);
        for _ in 0..ancount {
            let (name, new_pos) = Self::read_name(data, pos)?;
            pos = new_pos;
            if pos + 10 > data.len() {
                return None;
            }
            let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let rclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
            let ttl =
                u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
            let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
            pos += 10;
            if pos + rdlength > data.len() {
                return None;
            }
            let rdata = data[pos..pos + rdlength].to_vec();
            pos += rdlength;
            answers.push(DnsAnswer {
                name,
                rtype,
                rclass,
                ttl,
                rdata,
            });
        }

        Some(DnsMessage {
            id,
            direction,
            // Младшие четыре бита флагов и есть `RCODE`.
            rcode: (flags & 0x000F) as u8,
            queries,
            answers,
        })
    }

    fn read_name(data: &[u8], start: usize) -> Option<(String, usize)> {
        let mut labels = Vec::new();
        let mut pos = start;
        let mut jumped = false;
        let mut return_pos = 0;
        let mut jumps = 0;

        loop {
            if pos >= data.len() {
                return None;
            }
            let len = data[pos] as usize;

            if len == 0 {
                if !jumped {
                    return_pos = pos + 1;
                }
                break;
            }

            if len & 0xC0 == 0xC0 {
                if pos + 1 >= data.len() {
                    return None;
                }
                if !jumped {
                    return_pos = pos + 2;
                }
                let offset = ((len & 0x3F) << 8) | data[pos + 1] as usize;
                pos = offset;
                jumped = true;
                jumps += 1;
                if jumps > 10 {
                    return None;
                }
                continue;
            }

            pos += 1;
            if pos + len > data.len() {
                return None;
            }
            let label = String::from_utf8_lossy(&data[pos..pos + len]).to_string();
            labels.push(label);
            pos += len;
        }

        let name = labels.join(".");
        Some((name, return_pos))
    }
}
