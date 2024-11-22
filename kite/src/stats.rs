use std::{
    collections::HashMap,
    fmt,
    iter::Sum,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use num_traits::PrimInt;
use tokio::sync::Mutex;

use kite_ebpf_types::Endpoint as LowLevelEndpoint;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Endpoint {
    pub addr: IpAddr,
    pub port: u16,
}

impl From<LowLevelEndpoint> for Endpoint {
    fn from(endpoint: LowLevelEndpoint) -> Self {
        Self {
            addr: IpAddr::V4(Ipv4Addr::from(endpoint.addr)),
            port: endpoint.port,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct Latencies(Vec<u64>);

impl Latencies {
    pub fn push(&mut self, latency: u64) {
        self.0.push(latency);
    }

    pub fn into_inner(self) -> Vec<u64> {
        self.0
    }

    pub fn aggregated(&self) -> AggregatedMetric<u64> {
        self.0.clone().into()
    }
}

#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub request_count: u64,
    pub latencies: Latencies,
}

impl Stats {
    pub fn request_count(&self) -> u64 {
        self.request_count
    }

    pub fn latencies(&self) -> &[u64] {
        &self.latencies.0
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AggregatedMetric<N>
where
    N: PrimInt + Default + Sum,
{
    pub avg: f64,
    pub p50: N,
    pub p90: N,
    pub p99: N,
    pub max: N,
}

impl<N: PrimInt + Default + Sum> From<Vec<N>> for AggregatedMetric<N> {
    fn from(value: Vec<N>) -> Self {
        if value.len() == 0 {
            return Self::default();
        }
        let mut sorted = value;
        sorted.sort_unstable();
        let p50 = sorted[sorted.len() / 2];
        let p90 = sorted[(sorted.len() * 90) / 100];
        let p99 = sorted[(sorted.len() * 99) / 100];
        let max = sorted.last().copied().unwrap();
        let len = sorted.len() as f64;
        let avg = sorted.iter().map(|&x| x.to_f64().unwrap()).sum::<f64>() / len;

        AggregatedMetric {
            avg,
            p50,
            p90,
            p99,
            max,
        }
    }
}

impl fmt::Display for AggregatedMetric<u64> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "avg/p50/p90/p99/max {:.2}/{:.2}/{:.2}/{:.2}/{:.2}",
            self.avg, self.p50, self.p90, self.p99, self.max
        )
    }
}

pub type SharedStatsMap = Arc<Mutex<HashMap<Endpoint, Stats>>>;
