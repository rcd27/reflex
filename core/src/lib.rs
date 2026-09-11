// Обещание имени в докблоке ([`Name`]) держит компилятор, не читатель: битая ссылка — ошибка сборки
// документации, а не молчаливое предупреждение, которое ловят люди постфактум.
#![deny(rustdoc::broken_intra_doc_links)]

pub mod builder;
// ФУНКТОР В КАТЕГОРИЮ БЭКЕНДОВ (#295, срез 4): способность стала ОГРАНИЧЕНИЕМ, а не пометкой.
pub mod backend;
pub mod capability;
pub mod certify;
pub mod checksum;
pub mod clock;
pub mod colimit;
pub mod command;
pub mod debounce;
pub mod detector;
pub mod disclosure;
pub mod edge;
pub mod effect;
pub mod expiring_set;
pub mod fibre;
pub mod flow_table;
pub mod grid;
pub mod held;
pub mod interleave;
#[cfg(feature = "tls")]
pub mod l7;
pub mod local;
// ОБЛАСТЬ МАРКИ — объявленное владение битами вместо подразумеваемого. Не под фичей: закон о
// параметре, зависимостей нет, и нужен он всякому, кто делит марку с соседом по машине.
pub mod mark;
pub mod mealy;
pub mod meter;
pub mod notice;
pub mod parse;
pub mod serves;
// СКЛЕЙКА ПО СДВИГАМ — один закон на QUIC и на TLS поверх TCP. Не под фичей: зависимостей нет, а
// нужен он обоим.
pub mod splice;
pub mod stack;
pub mod tape;
// ЗАПИСАННЫЙ ПРОВОД — симуляционный источник (#295, срез 0). Под фичей, потому что читать файлы
// нужно не всякому потребителю: на коробке провод живой. Зависимостей нет — только `std`.
#[cfg(feature = "pcap")]
pub mod pcap;
pub mod role;
pub mod sight;
pub mod tap;
pub mod tempo;
pub mod timeout;
pub mod types;
pub mod watch;
pub mod word;

pub use tap::Tap;
pub use tempo::Tempo;

#[cfg(feature = "dns")]
pub mod dns;
#[cfg(feature = "quic")]
pub mod quic;
#[cfg(feature = "tls")]
pub mod tls;

pub use capability::{
    CanDrop, CanHold, CanInject, CanMark, CanModify, CanObserve, CanRefuse, CanRewrite, CanSever,
    Toward,
};
pub use command::{Command, InjectablePacket, ModifyPacket};
pub use detector::{
    Both, By, Changes, Contextual, DetectorEvent, LMap, RMap, Sensed, Signed, Stamped, Timed,
};
#[cfg(feature = "tls")]
pub use l7::L7;
pub use serves::Serves;
pub use stack::{AnyProtocol, Dns, Http, Protocol, Quic, Reads, Tcp, Tls, Udp};
