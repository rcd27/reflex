/// Backend can read a copy of each packet without interfering with its flow.
pub trait CanObserve {}

/// Backend can send new packets into the network.
pub trait CanInject {}

/// Backend can hold a packet pending a verdict (accept/drop/modify).
pub trait CanHold {}

/// Backend can modify a packet in-place before forwarding.
pub trait CanModify {}

/// Backend can drop a packet, preventing it from reaching its destination.
pub trait CanDrop {}
