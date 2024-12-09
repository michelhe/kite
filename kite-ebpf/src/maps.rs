use aya_ebpf::{
    bindings::{sk_action::SK_PASS, BPF_F_NO_PREALLOC},
    cty::c_long,
    macros::map,
    maps::{HashMap, PerCpuArray, PerfEventArray},
};
use kite_ebpf_types::{HTTPRequestEvent, PacketData};

use crate::contrack::HTTPConnectionState;

const MAX_CONNECTIONS: u32 = 10000;

#[map]
pub static KITE_CONTRACK: HashMap<u64, HTTPConnectionState> =
    HashMap::with_max_entries(MAX_CONNECTIONS, BPF_F_NO_PREALLOC);

#[map]
pub static EVENTS: PerfEventArray<HTTPRequestEvent> = PerfEventArray::new(0);

#[map]
pub static REQUEST_PACKETS: HashMap<u64, PacketData> =
    HashMap::with_max_entries(MAX_CONNECTIONS, 0);

/// A buffer to store temp TCP data.
#[map]
pub static mut SCRATCH_PACKET: PerCpuArray<PacketData> = PerCpuArray::with_max_entries(1, 0);

#[inline]
#[allow(static_mut_refs)]
pub fn get_scratch_packet() -> Result<&'static mut PacketData, c_long> {
    let event: &mut PacketData = unsafe {
        let ptr = SCRATCH_PACKET.get_ptr_mut(0).ok_or(SK_PASS)?;
        &mut *ptr
    };
    Ok(event)
}

#[map]
pub static mut SCRATCH_EVENT: PerCpuArray<HTTPRequestEvent> = PerCpuArray::with_max_entries(1, 0);

#[inline]
#[allow(static_mut_refs)]
pub fn get_scratch_event() -> Result<&'static mut HTTPRequestEvent, c_long> {
    let event = unsafe {
        let ptr = SCRATCH_EVENT.get_ptr_mut(0).ok_or(SK_PASS)?;
        &mut *ptr
    };
    Ok(event)
}
