use std::collections::HashMap;

use smallvec::SmallVec;

use crate::detector::DetectorEvent;
use crate::types::{Flow, TcpSegment};
use crate::Detector;

pub struct FlowTable<D: Detector<Input = TcpSegment>> {
    flows: HashMap<Flow, D>,
    make_detector: Box<dyn Fn(Flow) -> D + Send>,
}

impl<D: Detector<Input = TcpSegment>> FlowTable<D> {
    pub fn new(make_detector: impl Fn(Flow) -> D + Send + 'static) -> Self {
        Self {
            flows: HashMap::new(),
            make_detector: Box::new(make_detector),
        }
    }

    pub fn process(&mut self, segment: &TcpSegment) -> SmallVec<[D::Signal; 2]> {
        let flow = normalize_flow(&segment.flow);
        let detector = self
            .flows
            .remove(&flow)
            .unwrap_or_else(|| (self.make_detector)(flow.clone()));
        let (detector, signals) = detector.step(DetectorEvent::Packet(segment.clone()));
        self.flows.insert(flow, detector);
        signals
    }

    pub fn tick(&mut self) -> Vec<D::Signal> {
        let now = std::time::Instant::now();
        let mut all_signals = Vec::new();
        let flows: Vec<Flow> = self.flows.keys().cloned().collect();
        for flow in flows {
            if let Some(detector) = self.flows.remove(&flow) {
                let (detector, signals) = detector.step(DetectorEvent::Tick(now));
                all_signals.extend(signals);
                self.flows.insert(flow, detector);
            }
        }
        all_signals
    }

    pub fn get(&self, flow: &Flow) -> Option<&D> {
        self.flows.get(&normalize_flow(flow))
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }
}

fn normalize_flow(flow: &Flow) -> Flow {
    if flow.dst.port() == 443 || flow.dst.port() < 1024 {
        flow.clone()
    } else {
        flow.reversed()
    }
}
