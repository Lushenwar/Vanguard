//! Vanguard egress filter: a cgroup `connect()` hook that permits only
//! destinations present in an allowlist trie.
//!
//! Default deny. A `connect()` to an address with no matching prefix returns 0,
//! which the kernel turns into `EPERM` for the calling process. Absence of a
//! rule is a denial, exactly as it is in the userspace policy.
//!
//! Longest-prefix-match tries rather than hash maps, so a `/8` and a `/24`
//! inside it can both be present without the program needing any ordering
//! logic — the kernel picks the most specific match.
//!
//! # Status
//!
//! **Never compiled or loaded.** Written on a Windows-on-ARM workstation with
//! no Linux target available. Whoever first builds this should expect to fight
//! the verifier a little; the shape is right, the details may not be.

#![no_std]
#![no_main]

use aya_ebpf::bindings::lpm_trie_key;
use aya_ebpf::macros::{cgroup_sock_addr, map};
use aya_ebpf::maps::lpm_trie::{Key, LpmTrie};
use aya_ebpf::programs::SockAddrContext;

/// Allowed IPv4 prefixes. Keys are network byte order, matching the address as
/// it appears in the socket context — converting on this side would mean doing
/// it once per connect instead of once per rule at load time.
#[map(name = "ALLOW_V4")]
static ALLOW_V4: LpmTrie<u32, u8> = LpmTrie::with_max_entries(1024, 0);

/// Allowed IPv6 prefixes, as raw octets.
#[map(name = "ALLOW_V6")]
static ALLOW_V6: LpmTrie<[u8; 16], u8> = LpmTrie::with_max_entries(1024, 0);

/// Verdicts, in the encoding the cgroup hook expects.
const ALLOW: i32 = 1;
const DENY: i32 = 0;

#[cgroup_sock_addr(connect4)]
pub fn vanguard_connect4(ctx: SockAddrContext) -> i32 {
    match try_connect4(&ctx) {
        Ok(verdict) => verdict,
        // A program that cannot read its own context must not conclude
        // "allowed". Failing closed is the only safe direction here.
        Err(_) => DENY,
    }
}

fn try_connect4(ctx: &SockAddrContext) -> Result<i32, ()> {
    let addr = unsafe { (*ctx.sock_addr).user_ip4 };
    let key = Key::new(32, addr);
    Ok(match ALLOW_V4.get(&key) {
        Some(_) => ALLOW,
        None => DENY,
    })
}

#[cgroup_sock_addr(connect6)]
pub fn vanguard_connect6(ctx: SockAddrContext) -> i32 {
    match try_connect6(&ctx) {
        Ok(verdict) => verdict,
        Err(_) => DENY,
    }
}

fn try_connect6(ctx: &SockAddrContext) -> Result<i32, ()> {
    let words = unsafe { (*ctx.sock_addr).user_ip6 };
    let mut octets = [0u8; 16];
    let mut i = 0;
    // Unrolled by the loop bound rather than by iterator adapters: the verifier
    // is happier with a bounded counted loop than with anything it has to prove
    // terminates for itself.
    while i < 4 {
        let bytes = words[i].to_ne_bytes();
        octets[i * 4] = bytes[0];
        octets[i * 4 + 1] = bytes[1];
        octets[i * 4 + 2] = bytes[2];
        octets[i * 4 + 3] = bytes[3];
        i += 1;
    }

    let key = Key::new(128, octets);
    Ok(match ALLOW_V6.get(&key) {
        Some(_) => ALLOW,
        None => DENY,
    })
}

/// Silences an unused-import warning for the binding the `Key` type is built
/// on; keeping the import explicit documents the ABI this program depends on.
const _: Option<lpm_trie_key> = None;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Unreachable: the verifier rejects programs that can panic, so this exists
    // only to satisfy the compiler.
    loop {}
}
