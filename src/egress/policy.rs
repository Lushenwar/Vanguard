//! The egress allowlist: one place that decides whether a destination is
//! permitted, shared by every enforcement point.
//!
//! There is deliberately no rule that means "everything". An allowlist with a
//! wildcard is not an allowlist, and the one-character difference between
//! `allow = []` and `allow = ["*"]` is too small a gesture for a decision that
//! large. A deployment that genuinely wants unrestricted egress should not be
//! running an egress filter.
//!
//! **What actually stops a tool reaching the network today is not this module.**
//! The wasm linker is empty, so a tool has no host binding through which a
//! socket could be opened — a stronger guarantee than any filter, because the
//! syscall cannot be reached rather than being blocked once attempted. This
//! policy is the shared truth for the day a host binding or subprocess wrapper
//! is added, and the reference implementation the eBPF filter must agree with.

use std::fmt;
use std::net::IpAddr;

use crate::error::{Error, Result};

/// One allowlist entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    /// Exactly this hostname.
    Host(String),
    /// Any subdomain of this name — and *not* the name itself.
    ///
    /// `*.example.com` matching `example.com` would be a surprise in the
    /// permissive direction, and permissive surprises in an allowlist are the
    /// only kind that matter. List both if both are wanted.
    Suffix(String),
    Ip(IpAddr),
    Cidr {
        base: IpAddr,
        bits: u8,
    },
}

/// One entry plus the port it is restricted to, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub rule: Rule,
    /// `None` means any port. Narrowing to a port is encouraged but not forced:
    /// requiring it would push people toward `:0`-style placeholders.
    pub port: Option<u16>,
    /// The rule as written, for reporting. An operator debugging a denial wants
    /// to see their own text, not a normalised rendering of it.
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow { rule: String },
    Deny,
}

impl Verdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Verdict::Allow { .. })
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Verdict::Allow { rule } => write!(f, "ALLOW (matched {rule})"),
            Verdict::Deny => write!(f, "DENY"),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EgressPolicy {
    entries: Vec<Entry>,
}

impl EgressPolicy {
    /// Build from configuration. A malformed rule is an error, not a skip.
    ///
    /// Ignoring a rule it could not parse would leave an operator believing a
    /// destination is reachable when it is not — or worse, leave a typo'd rule
    /// silently doing nothing while the config file says otherwise.
    pub fn parse(rules: &[String]) -> Result<EgressPolicy> {
        let entries = rules
            .iter()
            .map(|r| parse_entry(r))
            .collect::<Result<Vec<_>>>()?;
        Ok(EgressPolicy { entries })
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Decide whether `host:port` may be reached.
    ///
    /// `host` may be a hostname or a literal address. Default deny: an empty
    /// policy refuses everything, and so does one whose rules simply do not
    /// match.
    pub fn decide(&self, host: &str, port: u16) -> Verdict {
        let host = normalise_host(host);
        let ip = host.parse::<IpAddr>().ok();

        for entry in &self.entries {
            if entry.port.is_some_and(|p| p != port) {
                continue;
            }
            let matched = match (&entry.rule, ip) {
                (Rule::Host(name), _) => *name == host,
                (Rule::Suffix(suffix), _) => {
                    // The leading dot is what stops `*.example.com` matching
                    // `evil-example.com`.
                    host.len() > suffix.len() + 1
                        && host.ends_with(suffix)
                        && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
                }
                (Rule::Ip(allowed), Some(actual)) => *allowed == actual,
                (Rule::Cidr { base, bits }, Some(actual)) => in_cidr(actual, *base, *bits),
                // An address rule cannot match a name. Resolving the name here
                // would make the decision depend on DNS, which an attacker who
                // controls a record could then move.
                (Rule::Ip(_) | Rule::Cidr { .. }, None) => false,
            };
            if matched {
                return Verdict::Allow {
                    rule: entry.source.clone(),
                };
            }
        }
        Verdict::Deny
    }
}

/// Lowercase, and drop the root label's trailing dot.
///
/// `EXAMPLE.COM.` and `example.com` are the same destination; treating them as
/// different is a bypass, not a nicety.
fn normalise_host(host: &str) -> String {
    let host = host.trim();
    let host = host.strip_suffix('.').unwrap_or(host);
    host.to_ascii_lowercase()
}

fn parse_entry(raw: &str) -> Result<Entry> {
    let source = raw.trim().to_string();
    if source.is_empty() {
        return Err(bad(raw, "empty rule"));
    }
    if source == "*" {
        return Err(bad(
            raw,
            "there is no allow-everything rule; an allowlist with a wildcard is not an allowlist",
        ));
    }

    let (target, port) = split_port(&source).ok_or_else(|| bad(raw, "malformed port"))?;
    if target.is_empty() {
        return Err(bad(raw, "no destination"));
    }

    let rule = if let Some(suffix) = target.strip_prefix("*.") {
        if suffix.is_empty() || suffix.contains('*') {
            return Err(bad(raw, "malformed wildcard"));
        }
        Rule::Suffix(normalise_host(suffix))
    } else if let Some((base, bits)) = target.split_once('/') {
        let base: IpAddr = base
            .parse()
            .map_err(|_| bad(raw, "CIDR base is not an IP address"))?;
        let bits: u8 = bits.parse().map_err(|_| bad(raw, "CIDR prefix"))?;
        let max = if base.is_ipv4() { 32 } else { 128 };
        if bits > max {
            return Err(bad(raw, &format!("CIDR prefix exceeds /{max}")));
        }
        Rule::Cidr { base, bits }
    } else if let Ok(ip) = target.parse::<IpAddr>() {
        Rule::Ip(ip)
    } else {
        if target.contains('*') {
            return Err(bad(raw, "wildcards are only valid as a leading `*.`"));
        }
        Rule::Host(normalise_host(target))
    };

    Ok(Entry { rule, port, source })
}

/// Split a trailing `:port`, honouring bracketed IPv6.
///
/// `::1:443` is genuinely ambiguous — it is a valid IPv6 address *and* looks
/// like an address with a port — so a bare IPv6 literal never gets a port, and
/// `[::1]:443` is the way to write one.
fn split_port(source: &str) -> Option<(&str, Option<u16>)> {
    if let Some(rest) = source.strip_prefix('[') {
        let (addr, tail) = rest.split_once(']')?;
        return match tail {
            "" => Some((addr, None)),
            _ => {
                let port = tail.strip_prefix(':')?.parse().ok()?;
                Some((addr, Some(port)))
            }
        };
    }

    match source.rsplit_once(':') {
        // More than one colon and no brackets: an unbracketed IPv6 literal.
        Some(_) if source.matches(':').count() > 1 => Some((source, None)),
        Some((target, port)) => Some((target, Some(port.parse().ok()?))),
        None => Some((source, None)),
    }
}

fn in_cidr(addr: IpAddr, base: IpAddr, bits: u8) -> bool {
    match (addr, base) {
        (IpAddr::V4(a), IpAddr::V4(b)) => prefix_eq(&a.octets(), &b.octets(), bits),
        (IpAddr::V6(a), IpAddr::V6(b)) => prefix_eq(&a.octets(), &b.octets(), bits),
        // No v4-in-v6 equivalence: an address family confusion is exactly the
        // kind of near-match that turns into a bypass.
        _ => false,
    }
}

fn prefix_eq(a: &[u8], b: &[u8], bits: u8) -> bool {
    let whole = (bits / 8) as usize;
    if a[..whole] != b[..whole] {
        return false;
    }
    let remainder = bits % 8;
    if remainder == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - remainder);
    a[whole] & mask == b[whole] & mask
}

fn bad(raw: &str, why: &str) -> Error {
    Error::Config(format!("egress rule {raw:?}: {why}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(rules: &[&str]) -> EgressPolicy {
        EgressPolicy::parse(&rules.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn an_empty_policy_denies_everything() {
        let p = policy(&[]);
        assert_eq!(p.decide("example.com", 443), Verdict::Deny);
        assert_eq!(p.decide("127.0.0.1", 80), Verdict::Deny);
    }

    #[test]
    fn an_exact_host_matches_only_itself() {
        let p = policy(&["example.com"]);
        assert!(p.decide("example.com", 443).is_allowed());
        assert!(!p.decide("sub.example.com", 443).is_allowed());
        assert!(!p.decide("example.com.evil.test", 443).is_allowed());
        assert!(!p.decide("notexample.com", 443).is_allowed());
    }

    #[test]
    fn host_matching_ignores_case_and_the_root_dot() {
        // Both are the same destination; treating them as different is a
        // bypass, not a nicety.
        let p = policy(&["Example.COM"]);
        assert!(p.decide("example.com", 443).is_allowed());
        assert!(p.decide("EXAMPLE.com.", 443).is_allowed());
    }

    #[test]
    fn a_wildcard_matches_subdomains_but_not_the_bare_name() {
        let p = policy(&["*.example.com"]);
        assert!(p.decide("api.example.com", 443).is_allowed());
        assert!(p.decide("a.b.example.com", 443).is_allowed());
        assert!(!p.decide("example.com", 443).is_allowed());
    }

    #[test]
    fn a_wildcard_cannot_be_escaped_by_a_lookalike_prefix() {
        // The attack the leading dot exists to stop.
        let p = policy(&["*.example.com"]);
        assert!(!p.decide("evil-example.com", 443).is_allowed());
        assert!(!p.decide("evilexample.com", 443).is_allowed());
        assert!(!p.decide("example.com.evil.test", 443).is_allowed());
    }

    #[test]
    fn ports_narrow_a_rule() {
        let p = policy(&["example.com:443"]);
        assert!(p.decide("example.com", 443).is_allowed());
        assert!(!p.decide("example.com", 80).is_allowed());

        let any = policy(&["example.com"]);
        assert!(any.decide("example.com", 80).is_allowed());
    }

    #[test]
    fn literal_addresses_match() {
        let p = policy(&["10.1.2.3", "[::1]:443"]);
        assert!(p.decide("10.1.2.3", 80).is_allowed());
        assert!(!p.decide("10.1.2.4", 80).is_allowed());
        assert!(p.decide("::1", 443).is_allowed());
        assert!(!p.decide("::1", 80).is_allowed());
    }

    #[test]
    fn cidr_ranges_match_on_prefix_bits() {
        let p = policy(&["10.0.0.0/8", "192.168.1.0/24", "2001:db8::/32"]);
        assert!(p.decide("10.255.255.255", 80).is_allowed());
        assert!(!p.decide("11.0.0.1", 80).is_allowed());
        assert!(p.decide("192.168.1.7", 80).is_allowed());
        assert!(!p.decide("192.168.2.7", 80).is_allowed());
        assert!(p.decide("2001:db8:dead::1", 80).is_allowed());
        assert!(!p.decide("2001:db9::1", 80).is_allowed());
    }

    #[test]
    fn cidr_handles_prefixes_that_are_not_byte_aligned() {
        let p = policy(&["10.0.0.0/12"]);
        assert!(p.decide("10.15.0.1", 80).is_allowed());
        assert!(!p.decide("10.16.0.1", 80).is_allowed());
    }

    #[test]
    fn address_families_do_not_cross() {
        // ::ffff:10.0.0.1 is 10.0.0.1 to some resolvers. Treating them as equal
        // is precisely the near-match that becomes a bypass.
        let p = policy(&["10.0.0.0/8"]);
        assert!(!p.decide("::ffff:10.0.0.1", 80).is_allowed());
    }

    #[test]
    fn an_address_rule_never_matches_a_name() {
        // Resolving here would make the decision depend on DNS, which whoever
        // controls the record could move afterwards.
        let p = policy(&["127.0.0.1"]);
        assert!(!p.decide("localhost", 80).is_allowed());
    }

    #[test]
    fn there_is_no_allow_everything_rule() {
        let err = EgressPolicy::parse(&["*".to_string()]).unwrap_err();
        assert!(err.to_string().contains("not an allowlist"), "{err}");
    }

    #[test]
    fn a_malformed_rule_is_an_error_not_a_skip() {
        // Silently dropping it would leave the config file claiming something
        // the runtime is not doing.
        for bad in [
            "",
            "10.0.0.0/33",
            "2001:db8::/129",
            "example.com:notaport",
            "ex*mple.com",
            "*.",
        ] {
            assert!(
                EgressPolicy::parse(&[bad.to_string()]).is_err(),
                "{bad:?} should not have parsed"
            );
        }
    }

    #[test]
    fn the_verdict_names_the_rule_that_allowed_it() {
        let p = policy(&["*.example.com", "10.0.0.0/8"]);
        assert_eq!(
            p.decide("api.example.com", 443),
            Verdict::Allow {
                rule: "*.example.com".into()
            }
        );
    }

    #[test]
    fn bracketed_and_bare_ipv6_parse_the_same_way() {
        let bare = policy(&["2001:db8::1"]);
        assert!(bare.decide("2001:db8::1", 9999).is_allowed());
        let bracketed = policy(&["[2001:db8::1]"]);
        assert!(bracketed.decide("2001:db8::1", 9999).is_allowed());
    }
}
