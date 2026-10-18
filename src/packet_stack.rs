use std::collections::VecDeque;

use smoltcp::{
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    time::Instant,
};

#[derive(Default)]
pub(crate) struct Queue {
    pub input: VecDeque<Vec<u8>>,
    pub output: VecDeque<Vec<u8>>,
}

pub(crate) struct Received(Vec<u8>);
pub(crate) struct Transmit<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for Received {
    fn consume<Output, Function: FnOnce(&[u8]) -> Output>(self, function: Function) -> Output {
        function(&self.0)
    }
}

impl TxToken for Transmit<'_> {
    fn consume<Output, Function: FnOnce(&mut [u8]) -> Output>(
        self,
        length: usize,
        function: Function,
    ) -> Output {
        let mut bytes = vec![0; length];
        let result = function(&mut bytes);
        self.0.push_back(bytes);
        result
    }
}

impl Device for Queue {
    type RxToken<'a> = Received;
    type TxToken<'a> = Transmit<'a>;

    fn receive(&mut self, _: Instant) -> Option<(Received, Transmit<'_>)> {
        if self.output.len() >= 256 {
            return None;
        }
        self.input
            .pop_front()
            .map(|bytes| (Received(bytes), Transmit(&mut self.output)))
    }

    fn transmit(&mut self, _: Instant) -> Option<Transmit<'_>> {
        (self.output.len() < 256).then_some(Transmit(&mut self.output))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = 1280;
        capabilities
    }
}
