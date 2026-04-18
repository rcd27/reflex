#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpTimestamps {
    pub ts_val: u32,
    pub ts_ecr: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TcpOptions {
    pub timestamps: Option<TcpTimestamps>,
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
}

impl TcpOptions {
    pub fn parse(data: &[u8]) -> Self {
        let mut opts = TcpOptions::default();
        let mut i = 0;

        while i < data.len() {
            let kind = data[i];
            match kind {
                0 => break,
                1 => {
                    i += 1;
                    continue;
                }
                _ => {
                    if i + 1 >= data.len() {
                        break;
                    }
                    let len = data[i + 1] as usize;
                    if len < 2 || i + len > data.len() {
                        break;
                    }

                    match kind {
                        2 if len == 4 => {
                            opts.mss = Some(u16::from_be_bytes([data[i + 2], data[i + 3]]));
                        }
                        3 if len == 3 => {
                            opts.window_scale = Some(data[i + 2]);
                        }
                        8 if len == 10 => {
                            opts.timestamps = Some(TcpTimestamps {
                                ts_val: u32::from_be_bytes([
                                    data[i + 2],
                                    data[i + 3],
                                    data[i + 4],
                                    data[i + 5],
                                ]),
                                ts_ecr: u32::from_be_bytes([
                                    data[i + 6],
                                    data[i + 7],
                                    data[i + 8],
                                    data[i + 9],
                                ]),
                            });
                        }
                        _ => {}
                    }

                    i += len;
                }
            }
        }

        opts
    }
}
