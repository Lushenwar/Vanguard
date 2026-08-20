//! eBPF enforcement at the socket layer. Linux only, behind the `ebpf` feature.
//!
//! # What this layer can and cannot do
//!
//! A `cgroup/connect4` hook sees a **destination address**. It does not see a
//! hostname, because by the time `connect()` is called the name is long gone —
//! resolved, cached, and forgotten. So the IP and CIDR rules in an
//! [`EgressPolicy`] are enforceable here and the hostname rules are **not**.
//!
//! That is not a limitation to paper over. A filter that silently ignored
//! `*.example.com` would leave an operator believing a rule is enforced when
//! nothing is enforcing it, which is worse than having no filter at all —
//! [`Filter::attach`] therefore refuses a policy whose hostname rules it cannot
//! honour, unless the caller explicitly acknowledges that they are enforced
//! elsewhere.
//!
//! Hostname rules belong at the layer that still knows the name: the host
//! binding that opens the connection, calling [`EgressPolicy::decide`] before it
//! resolves anything. This module is defence in depth underneath that, for the
//! address a connection actually goes to rather than the one a name claimed to
//! resolve to.
//!
//! # Status
//!
//! **Written, not exercised.** This workstation is Windows on ARM; the code
//! below has never been compiled against a Linux target or loaded into a
//! kernel. Treat it as a starting point for whoever runs Vanguard on Linux, not
//! as a working feature. The BPF program it loads lives in `bpf/` and is built
//! separately — see BUILDING below.

use std::path::Path;

use crate::egress::policy::{EgressPolicy, Rule};
use crate::error::{Error, Result};

/// Rules this layer cannot enforce, with the reason.
///
/// Returned rather than logged so a caller has to decide what to do about them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unenforceable {
    pub rule: String,
    pub why: &'static str,
}

/// Which rules a socket-layer filter can and cannot honour.
pub fn triage(policy: &EgressPolicy) -> (usize, Vec<Unenforceable>) {
    let mut enforceable = 0;
    let mut skipped = Vec::new();

    for entry in policy.entries() {
        match entry.rule {
            Rule::Ip(_) | Rule::Cidr { .. } => enforceable += 1,
            Rule::Host(_) | Rule::Suffix(_) => skipped.push(Unenforceable {
                rule: entry.source.clone(),
                why: "connect() sees an address, not a name; enforce this at the host binding",
            }),
        }
    }
    (enforceable, skipped)
}

/// An attached filter. Detaches on drop.
///
/// `Debug` reports the rule counts rather than the loaded object: what an
/// operator needs to see is how much of the policy this layer is actually
/// carrying.
pub struct Filter {
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    _bpf: aya::Ebpf,
    enforced: usize,
    skipped: Vec<Unenforceable>,
}

impl std::fmt::Debug for Filter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Filter")
            .field("enforced", &self.enforced)
            .field("skipped", &self.skipped.len())
            .finish()
    }
}

impl Filter {
    pub fn enforced_rules(&self) -> usize {
        self.enforced
    }

    pub fn skipped_rules(&self) -> &[Unenforceable] {
        &self.skipped
    }

    /// Whether this build can enforce anything at the socket layer at all.
    pub const fn available() -> bool {
        cfg!(all(target_os = "linux", feature = "ebpf"))
    }

    /// Load the program, populate the allowlist maps, and attach to `cgroup`.
    ///
    /// `accept_unenforceable` must be true if the policy contains hostname
    /// rules; passing false is how a caller says "I expect this filter to be
    /// the whole story", and it should fail loudly when it is not.
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub fn attach(
        policy: &EgressPolicy,
        cgroup: &Path,
        accept_unenforceable: bool,
    ) -> Result<Filter> {
        use aya::maps::lpm_trie::{Key, LpmTrie};
        use aya::programs::{CgroupAttachMode, CgroupSockAddr};

        let (enforced, skipped) = triage(policy);
        if !skipped.is_empty() && !accept_unenforceable {
            return Err(Error::Config(format!(
                "egress policy has {} rule(s) this filter cannot enforce: {}",
                skipped.len(),
                skipped
                    .iter()
                    .map(|s| s.rule.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }

        let object = std::env::var("VANGUARD_BPF_OBJECT")
            .unwrap_or_else(|_| "/usr/lib/vanguard/vanguard-egress.o".to_string());
        let mut bpf = aya::Ebpf::load_file(&object)
            .map_err(|e| Error::Config(format!("loading {object}: {e}")))?;

        // Longest-prefix-match tries, so a /8 and a /24 inside it both work and
        // the more specific one wins without any ordering rules in the program.
        {
            let mut v4: LpmTrie<_, u32, u8> = LpmTrie::try_from(
                bpf.map_mut("ALLOW_V4")
                    .ok_or_else(|| Error::Config("BPF object has no ALLOW_V4 map".into()))?,
            )
            .map_err(|e| Error::Config(e.to_string()))?;
            let mut v6: LpmTrie<_, [u8; 16], u8> = LpmTrie::try_from(
                bpf.map_mut("ALLOW_V6")
                    .ok_or_else(|| Error::Config("BPF object has no ALLOW_V6 map".into()))?,
            )
            .map_err(|e| Error::Config(e.to_string()))?;

            for entry in policy.entries() {
                let (addr, bits) = match entry.rule {
                    Rule::Ip(ip) => (ip, if ip.is_ipv4() { 32 } else { 128 }),
                    Rule::Cidr { base, bits } => (base, bits),
                    _ => continue,
                };
                match addr {
                    std::net::IpAddr::V4(a) => v4
                        // Network byte order: the program reads the address
                        // straight out of the socket context, where it is
                        // big-endian.
                        .insert(&Key::new(bits as u32, u32::from(a).to_be()), 1, 0)
                        .map_err(|e| Error::Config(e.to_string()))?,
                    std::net::IpAddr::V6(a) => v6
                        .insert(&Key::new(bits as u32, a.octets()), 1, 0)
                        .map_err(|e| Error::Config(e.to_string()))?,
                }
            }
        }

        for name in ["vanguard_connect4", "vanguard_connect6"] {
            let program: &mut CgroupSockAddr = bpf
                .program_mut(name)
                .ok_or_else(|| Error::Config(format!("BPF object has no {name} program")))?
                .try_into()
                .map_err(|e| Error::Config(format!("{name}: {e}")))?;
            program
                .load()
                .map_err(|e| Error::Config(format!("{name}: {e}")))?;
            let cgroup_file = std::fs::File::open(cgroup)?;
            program
                .attach(cgroup_file, CgroupAttachMode::Single)
                .map_err(|e| {
                    Error::Config(format!("attaching {name} to {}: {e}", cgroup.display()))
                })?;
        }

        Ok(Filter {
            _bpf: bpf,
            enforced,
            skipped,
        })
    }

    /// Everywhere else: say so, clearly, rather than pretending to attach.
    ///
    /// Returning a no-op `Filter` here would be the most dangerous possible
    /// behaviour — a caller would believe egress was filtered when nothing was
    /// loaded. The risk taxonomy calls this "falling back to permissive
    /// networking", and the only safe fallback is a loud error.
    #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
    pub fn attach(
        _policy: &EgressPolicy,
        _cgroup: &Path,
        _accept_unenforceable: bool,
    ) -> Result<Filter> {
        Err(Error::Config(
            "eBPF egress filtering is unavailable in this build: it requires Linux \
             and the `ebpf` feature. Nothing was attached."
                .into(),
        ))
    }
}

// BUILDING (Linux)
//
//   1. The BPF program is a separate crate in `bpf/`, outside the workspace so
//      an ordinary `cargo build` does not try to compile it for the host.
//
//        rustup toolchain install nightly --component rust-src
//        cargo install bpf-linker
//        cd bpf && cargo +nightly build --release \
//            -Z build-std=core --target bpfel-unknown-none
//
//   2. Point the loader at the artifact and enable the feature:
//
//        export VANGUARD_BPF_OBJECT=bpf/target/bpfel-unknown-none/release/vanguard-egress
//        cargo build --features ebpf
//
//   3. Attaching to a cgroup needs CAP_BPF and CAP_NET_ADMIN, and a kernel of
//      5.15 or newer. Older kernels fail at attach; per the risk taxonomy, that
//      failure must stay an error rather than becoming a permissive fallback.

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(rules: &[&str]) -> EgressPolicy {
        EgressPolicy::parse(&rules.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn triage_separates_addresses_from_names() {
        let p = policy(&["10.0.0.0/8", "*.example.com", "1.2.3.4", "example.com"]);
        let (enforceable, skipped) = triage(&p);
        assert_eq!(enforceable, 2);
        assert_eq!(
            skipped.iter().map(|s| s.rule.as_str()).collect::<Vec<_>>(),
            vec!["*.example.com", "example.com"]
        );
    }

    #[test]
    fn an_address_only_policy_is_fully_enforceable() {
        let (enforceable, skipped) = triage(&policy(&["10.0.0.0/8", "[::1]:443"]));
        assert_eq!(enforceable, 2);
        assert!(skipped.is_empty());
    }

    #[test]
    fn attaching_fails_loudly_where_it_cannot_work() {
        // The important half of this on a non-Linux host: no silent no-op.
        // A caller must never come away believing egress is filtered.
        if Filter::available() {
            return;
        }
        let err = Filter::attach(&policy(&["10.0.0.0/8"]), Path::new("/sys/fs/cgroup"), false)
            .unwrap_err();
        assert!(err.to_string().contains("Nothing was attached"), "{err}");
    }
}
