use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use aya::util::KernelVersion;
use log::debug;

/// We use eBPF features that are only available in newer kernels. Check if the kernel is supported.
pub fn check_kernel_supported() -> anyhow::Result<()> {
    let version = KernelVersion::current()?;
    if version < KernelVersion::new(4, 10, 0) {
        return Err(anyhow::anyhow!(
            "Kernel version {} is not supported. Must be at least 4.10.0",
            version
        ));
    }
    Ok(())
}

pub fn try_remove_rlimit() {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }
}

/// Copied from unstable std::net::Ipv4Addr::is_global
#[inline]
const fn is_global_ip4(ip4: &Ipv4Addr) -> bool {
    !(ip4.octets()[0] == 0 // "This network"
        || ip4.is_private()
        || ip4.octets()[0] == 100 && (ip4.octets()[1] & 0b1100_0000 == 0b0100_0000) // ip4.is_shared()
        || ip4.is_loopback()
        || ip4.is_link_local()
        // addresses reserved for future protocols (`192.0.0.0/24`)
        // .9 and .10 are documented as globally reachable so they're excluded
        || (
            ip4.octets()[0] == 192 && ip4.octets()[1] == 0 && ip4.octets()[2] == 0
            && ip4.octets()[3] != 9 && ip4.octets()[3] != 10
        )
        || ip4.is_documentation()
        || ip4.octets()[0] == 198 && (ip4.octets()[1] & 0xfe) == 18 // ip4.is_benchmarking()
        || ip4.octets()[0] & 240 == 240 && !ip4.is_broadcast() // ip4.is_reserved()
        || ip4.is_broadcast())
}

/// Copied from unstable std::net::Ipv6Addr::is_global
#[inline]
const fn is_global_ip6(ip6: &Ipv6Addr) -> bool {
    !(
        ip6.is_unspecified()
        || ip6.is_loopback()
        // IPv4-mapped Address (`::ffff:0:0/96`)
        || matches!(ip6.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
        // IPv4-IPv6 Translat. (`64:ff9b:1::/48`)
        || matches!(ip6.segments(), [0x64, 0xff9b, 1, _, _, _, _, _])
        // Discard-Only Address Block (`100::/64`)
        || matches!(ip6.segments(), [0x100, 0, 0, 0, _, _, _, _])
        // IETF Protocol Assignments (`2001::/23`)
        || (matches!(ip6.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200)
            && !(
                // Port Control Protocol Anycast (`2001:1::1`)
                u128::from_be_bytes(ip6.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0001
                // Traversal Using Relays around NAT Anycast (`2001:1::2`)
                || u128::from_be_bytes(ip6.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0002
                // AMT (`2001:3::/32`)
                || matches!(ip6.segments(), [0x2001, 3, _, _, _, _, _, _])
                // AS112-v6 (`2001:4:112::/48`)
                || matches!(ip6.segments(), [0x2001, 4, 0x112, _, _, _, _, _])
                // ORCHIDv2 (`2001:20::/28`)
                // Drone Remote ID Protocol Entity Tags (DETs) Prefix (`2001:30::/28`)`
                || matches!(ip6.segments(), [0x2001, b, _, _, _, _, _, _] if b >= 0x20 && b <= 0x3F)
            ))
        // 6to4 (`2002::/16`) – it's not explicitly documented as globally reachable,
        // IANA says N/A.
        || matches!(ip6.segments(), [0x2002, _, _, _, _, _, _, _])
        || (ip6.segments()[0] == 0x2001) && (ip6.segments()[1] == 0xdb8) // ip6.is_documentation()
        || (ip6.segments()[0] & 0xfe00) == 0xfc00 // ip6.is_unique_local()
        || (ip6.segments()[0] & 0xffc0) == 0xfe80
        // ip6.is_unicast_link_local()
    )
}

pub fn is_global_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_global_ip4(&ip),
        IpAddr::V6(ip) => is_global_ip6(&ip),
    }
}
