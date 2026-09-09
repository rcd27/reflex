//! Обход и сборка TLV netlink — общие для ctnetlink и очереди. Одно место: два обхода одних байтов
//! разошлись бы молча при зелёной сборке (тот же шов, что и один чеканщик `CTA_*`).

const ATTR_HDR: usize = 4;
const NESTED: u16 = 0x8000;

pub(crate) const fn aligned(len: usize) -> usize {
    (len + 3) & !3
}

pub(crate) fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    bytes
        .get(at..at + 2)
        .map(|two| u16::from_ne_bytes([two[0], two[1]]))
}

pub(crate) fn be16_at(bytes: &[u8], at: usize) -> Option<u16> {
    bytes
        .get(at..at + 2)
        .map(|two| u16::from_be_bytes([two[0], two[1]]))
}

pub(crate) fn be32_at(bytes: &[u8], at: usize) -> Option<u32> {
    bytes
        .get(at..at + 4)
        .map(|four| u32::from_be_bytes([four[0], four[1], four[2], four[3]]))
}

pub(crate) fn be64_at(bytes: &[u8], at: usize) -> Option<u64> {
    bytes.get(at..at + 8).map(|eight| {
        u64::from_be_bytes([
            eight[0], eight[1], eight[2], eight[3], eight[4], eight[5], eight[6], eight[7],
        ])
    })
}

pub(crate) fn i32_at(bytes: &[u8], at: usize) -> Option<i32> {
    bytes
        .get(at..at + 4)
        .map(|four| i32::from_ne_bytes([four[0], four[1], four[2], four[3]]))
}

/// Обход TLV одного уровня. Длина в заголовке включает его самого; короче заголовка — обрыв, обход
/// прекращается, а не пропускает байты наугад.
pub(crate) struct Attrs<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Attrs<'a> {
    type Item = (u16, &'a [u8]);

    /// Выход один, и он гасит остаток. Прежде обрыв уходил через `?`, не тронув `self.rest`:
    /// итератор возвращал `None`, а на следующем шаге снова `Some` те же байты. Сверка длины
    /// выглядела дублем `.get`, но держала фьюзность — теперь её держит единственная ветка отказа.
    fn next(&mut self) -> Option<(u16, &'a [u8])> {
        match (u16_at(self.rest, 0), u16_at(self.rest, 2)) {
            (Some(len), Some(kind)) => match self.rest.get(ATTR_HDR..len as usize) {
                Some(body) => {
                    self.rest = self.rest.get(aligned(len as usize)..).unwrap_or(&[]);
                    Some((kind & !NESTED, body))
                }
                None => {
                    self.rest = &[];
                    None
                }
            },
            (Some(_), _) | (None, _) => {
                self.rest = &[];
                None
            }
        }
    }
}

pub(crate) fn attrs(body: &[u8]) -> Attrs<'_> {
    Attrs { rest: body }
}

/// Один атрибут: заголовок и тело, выровненные до четырёх. Длина в заголовке паддинг НЕ считает —
/// эта разница стоила апстриму `nfq` отдельного исправления, и обход выше её ждёт.
///
/// Сборка — путь ЗАПИСИ (вердикт/конфигурация очереди), потому под `nfqueue`; дамп только читает.
/// `test` — чтобы законы обратимости жили в этом же модуле и под `--features conntrack`.
#[cfg(any(test, feature = "nfqueue"))]
pub(crate) fn tlv(kind: u16, body: &[u8]) -> Vec<u8> {
    let len = (ATTR_HDR + body.len()) as u16;
    len.to_ne_bytes()
        .into_iter()
        .chain(kind.to_ne_bytes())
        .chain(body.iter().copied())
        .chain(std::iter::repeat_n(0u8, aligned(body.len()) - body.len()))
        .collect()
}

/// Вложенный атрибут — тот же TLV с объявленной вложенностью (бит снимается на чтении в [`Attrs`]).
#[cfg(any(test, feature = "nfqueue"))]
pub(crate) fn nested(kind: u16, body: &[u8]) -> Vec<u8> {
    tlv(kind | NESTED, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Длина в заголовке атрибута считает заголовок и тело, но НЕ паддинг: у ядра эта разница
    /// стоила апстриму крейта `nfq` отдельного исправления (июнь 2026).
    #[test]
    fn attribute_length_excludes_padding() {
        let built = tlv(7, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(built.len(), 8, "тело выровнено до четырёх");
        assert_eq!(u16_at(&built, 0), Some(7), "длина = 4 заголовка + 3 тела");
        assert_eq!(u16_at(&built, 2), Some(7), "тип на месте");
        assert_eq!(&built[4..7], &[0xAA, 0xBB, 0xCC]);
    }

    /// Сборка и обход — обратны друг другу.
    #[test]
    fn built_attributes_read_back() {
        let body: Vec<u8> = tlv(1, &[1, 2, 3]).into_iter().chain(tlv(2, &[4])).collect();
        let read: Vec<(u16, Vec<u8>)> = attrs(&body).map(|(k, v)| (k, v.to_vec())).collect();
        assert_eq!(read, vec![(1, vec![1, 2, 3]), (2, vec![4])]);
    }

    /// Бит вложенности снимается на чтении: тип атрибута называет предмет, не форму.
    #[test]
    fn nested_bit_is_stripped_on_read() {
        let inner = tlv(3, &[9]);
        let body = nested(5, &inner);
        let read: Vec<u16> = attrs(&body).map(|(k, _)| k).collect();
        assert_eq!(read, vec![5], "тип без бита 0x8000");
    }

    /// Обрыв гасит обход целиком: фьюзность держит единственная ветка отказа.
    #[test]
    fn truncated_attribute_stops_the_walk() {
        let mut body = tlv(1, &[1, 2, 3, 4, 5, 6]);
        body.truncate(6);
        assert_eq!(attrs(&body).count(), 0);
    }
}
