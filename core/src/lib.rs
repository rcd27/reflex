pub mod builder;
// ФУНКТОР В КАТЕГОРИЮ БЭКЕНДОВ (#295, срез 4): способность стала ОГРАНИЧЕНИЕМ, а не пометкой.
pub mod backend;
pub mod capability;
// ОБЪЕКТЫ И МОРФИЗМЫ КАТЕГОРИИ (#295, срез 2): стадия — тип, морфизм — метод на своей стадии.
pub mod category;
pub mod checksum;
pub mod command;
pub mod detector;
pub mod expiring_set;
pub mod ext;
pub mod flow_table;
pub mod guard;
pub mod parse;
// ЗАПИСАННЫЙ ПРОВОД — симуляционный источник (#295, срез 0). Под фичей, потому что читать файлы
// нужно не всякому потребителю: на коробке провод живой. Зависимостей нет — только `std`.
#[cfg(feature = "pcap")]
pub mod pcap;
pub mod reactor;
pub mod role;
pub mod stream;
pub mod tap;
pub mod tempo;
pub mod types;

pub use tap::Tap;
pub use tempo::Tempo;

#[cfg(feature = "dns")]
pub mod dns;
#[cfg(feature = "quic")]
pub mod quic;
#[cfg(feature = "tls")]
pub mod tls;

pub use capability::{CanDrop, CanHold, CanInject, CanModify, CanObserve};
pub use command::{Command, InjectablePacket, ModifyPacket};
pub use detector::{
    And, Changes, Contextual, Detector, DetectorEvent, DetectorExt, LMap, RMap, Timed,
};
pub use ext::ReflexExt;
pub use guard::{CleanupReport, TrafficGuard};
pub use reactor::{drive, drive_observed, group_by_reactor, Reactor, Transition};
