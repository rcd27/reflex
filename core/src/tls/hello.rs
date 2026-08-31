/// Build a minimal TLS 1.2 ClientHello with SNI extension.
pub fn build_client_hello(domain: &str) -> Vec<u8> {
    let sni_bytes = domain.as_bytes();
    let sni_list_len = 1 + 2 + sni_bytes.len();
    let sni_ext_data_len = 2 + sni_list_len;
    let extensions_len = 2 + 2 + sni_ext_data_len;
    let ch_body_len = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extensions_len;
    let handshake_len = 1 + 3 + ch_body_len;
    let record_len = handshake_len;

    let mut pkt = Vec::with_capacity(5 + record_len);
    pkt.push(0x16);
    pkt.extend_from_slice(&[0x03, 0x01]);
    pkt.extend_from_slice(&(record_len as u16).to_be_bytes());
    pkt.push(0x01);
    let body_len = ch_body_len as u32;
    pkt.push((body_len >> 16) as u8);
    pkt.push((body_len >> 8) as u8);
    pkt.push(body_len as u8);
    pkt.extend_from_slice(&[0x03, 0x03]);
    pkt.extend_from_slice(&[0xAA; 32]);
    pkt.push(0x00);
    pkt.extend_from_slice(&[0x00, 0x02]);
    pkt.extend_from_slice(&[0x00, 0x2F]);
    pkt.push(0x01);
    pkt.push(0x00);
    pkt.extend_from_slice(&(extensions_len as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
    pkt.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
    pkt.push(0x00);
    pkt.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    pkt.extend_from_slice(sni_bytes);
    pkt
}

/// Переписать SNI в ГОТОВОМ ClientHello, сохранив всё остальное.
///
/// Зачем примитив, а не «собрать hello заново»: правдоподобие для DPI создаётся набором
/// расширений, ciphersuites и key_share живого клиента — синтезировать это дороже, чем взять
/// снятый с провода образец и подставить в него нужное имя. Потребители — проба Зонда (ходит
/// к цели hello'ом реального клиента) и decoy-техники десинка.
///
/// Переписать одно поле мало: длина имени меняет ПЯТЬ вложенных длин (запись → handshake →
/// блок расширений → расширение SNI → список имён → само имя). Пропусти одну — получишь
/// hello, который парсер прочитает, а сервер отвергнет, и разница проявится только на проводе.
///
/// `None`, если вход не ClientHello, в нём нет SNI, или новое имя не помещается в 16 бит.
pub fn rewrite_sni(hello: &[u8], new_name: &str) -> Option<Vec<u8>> {
    let old = super::sni(hello)?;
    let (name_off, old_len) = old.span;
    let new_len = new_name.len();
    if new_len > u16::MAX as usize - 5 {
        return None;
    }

    // Байты вокруг имени сохраняются как есть — правдоподобие живого клиента в них и живёт.
    let mut out = Vec::with_capacity(hello.len() + new_len - old_len);
    out.extend_from_slice(&hello[..name_off]);
    out.extend_from_slice(new_name.as_bytes());
    out.extend_from_slice(&hello[name_off + old_len..]);

    // ПЯТЬ ДЛИН, каждая от своего начала. Смещения известны точно: имя лежит в конце цепочки
    // «record → handshake → extensions → ext SNI → список», и все заголовки — ПЕРЕД ним.
    let delta = new_len as isize - old_len as isize;
    let поправить16 = |buf: &mut Vec<u8>, at: usize| -> Option<()> {
        let v = u16::from_be_bytes([*buf.get(at)?, *buf.get(at + 1)?]) as isize + delta;
        let v = u16::try_from(v).ok()?;
        buf[at..at + 2].copy_from_slice(&v.to_be_bytes());
        Some(())
    };

    поправить16(&mut out, 3)?; // длина TLS-записи
                               // Длина handshake — ТРИ байта (u24), не два: правка её как u16 молча испортила бы старший.
    let hs = u32::from_be_bytes([0, out[6], out[7], out[8]]) as isize + delta;
    let hs = u32::try_from(hs).ok()?;
    out[6..9].copy_from_slice(&hs.to_be_bytes()[1..4]);

    // Позиции блока расширений и заголовка SNI-расширения — те же, что нашёл парс: имя
    // лежит на `name_off`, а заголовки от него на фиксированных смещениях назад.
    // list_len(2) + name_type(1) + name_len(2) = 5 байт непосредственно перед именем;
    // перед ними ext_type(2) + ext_len(2).
    поправить16(&mut out, name_off - 2)?; // длина имени
    поправить16(&mut out, name_off - 5)?; // длина списка имён
    поправить16(&mut out, name_off - 7)?; // длина расширения SNI

    // Длина всего блока расширений: он начинается после compression_methods, а его заголовок
    // ищется тем же проходом, что и парс — от начала тела ClientHello.
    let ext_total_at = extensions_length_offset(hello)?;
    поправить16(&mut out, ext_total_at)?;
    Some(out)
}

/// Смещение поля «длина блока расширений» в ClientHello. Отдельная функция, потому что до него
/// нужно пройти session_id/cipher_suites/compression_methods переменной длины.
fn extensions_length_offset(hello: &[u8]) -> Option<usize> {
    let mut pos = 5 + 38; // record(5) + handshake_type(1)+len(3)+version(2)+random(32)
    pos += 1 + *hello.get(pos)? as usize; // session_id
    let cs = u16::from_be_bytes([*hello.get(pos)?, *hello.get(pos + 1)?]) as usize;
    pos += 2 + cs; // cipher_suites
    pos += 1 + *hello.get(pos)? as usize; // compression_methods
    (pos + 2 <= hello.len()).then_some(pos)
}
