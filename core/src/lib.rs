pub mod capability;
pub mod detector;
pub mod ext;
pub mod stream;

pub use capability::{CanDrop, CanHold, CanInject, CanModify, CanObserve};
pub use detector::Detector;
pub use ext::ReflexExt;
