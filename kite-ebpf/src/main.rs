#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::sk_action::SK_PASS,
    macros::{cgroup_skb, cgroup_sock},
    programs::{SkBuffContext, SockContext},
};
use aya_log_ebpf::error;

mod contrack;
mod http;
mod maps;
mod programs;
mod tcp;
mod utils;

#[cgroup_skb]
pub fn kite_ingress(ctx: SkBuffContext) -> i32 {
    match programs::cgroup_skb::cgroup_skb_program(&ctx, programs::cgroup_skb::ProgramType::Ingress)
    {
        Ok(res) => res as i32,
        Err(err) => {
            error!(&ctx, "kite_ingress - Error: {}", err);
            SK_PASS as i32
        }
    }
}

#[cgroup_skb]
pub fn kite_egress(ctx: SkBuffContext) -> i32 {
    match programs::cgroup_skb::cgroup_skb_program(&ctx, programs::cgroup_skb::ProgramType::Egress)
    {
        Ok(res) => res as i32,
        Err(err) => {
            error!(&ctx, "kite_egress - Error: {}", err);
            SK_PASS as i32
        }
    }
}

#[cgroup_sock(sock_release)]
/// This program is called when a socket is released. We use it to clean up the connection tracking.
pub fn kite_sock_release(ctx: SockContext) -> i32 {
    match programs::cgroup_sock::cgroup_sock_release(&ctx) {
        Ok(res) => res,
        Err(err) => {
            error!(&ctx, "kite_sock_release - Error: {}", err);
            1
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
