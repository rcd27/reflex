use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Mac(pub [u8; 6]);

/// Запись `aa:bb:cc:dd:ee:ff` — ровно шесть шестнадцатеричных байт; иное — не MAC.
impl std::str::FromStr for Mac {
    type Err = ();

    fn from_str(text: &str) -> Result<Mac, ()> {
        text.split(':')
            .map(|byte| {
                (1..=2)
                    .contains(&byte.len())
                    .then(|| u8::from_str_radix(byte, 16).ok())
                    .flatten()
                    .ok_or(())
            })
            .collect::<Result<Vec<u8>, ()>>()
            .and_then(|bytes| <[u8; 6]>::try_from(bytes).map_err(|_count| ()))
            .map(Mac)
    }
}

impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Запись и печать обратимы; пять байт, семь байт и байт из трёх цифр — не MAC.
    #[test]
    fn a_mac_reads_back_what_it_prints_and_nothing_else() {
        let mac = Mac([0x60, 0xe3, 0x27, 0xf7, 0xbb, 0xaf]);
        assert_eq!(mac.to_string().parse::<Mac>(), Ok(mac));
        assert_eq!(
            "2:81:0:0:0:1".parse::<Mac>(),
            Ok(Mac([2, 0x81, 0, 0, 0, 1]))
        );
        [
            "60:e3:27:f7:bb",
            "60:e3:27:f7:bb:af:00",
            "60:e3:27:f7:bb:aff",
            "60:e3:27:f7:bb:zz",
            "",
        ]
        .iter()
        .for_each(|bad| assert_eq!(bad.parse::<Mac>(), Err(()), "{bad}"));
    }
}
