//! Phase 7 tests: the egress allowlist, and honesty about what enforces it.
//!
//! The eBPF filter itself cannot be tested here — it needs Linux, a kernel, and
//! a cgroup. What is testable everywhere is the policy every enforcement point
//! consults, and the refusal to pretend enforcement is happening when it is not.

use vanguard::config::Config;
use vanguard::egress::filter::{self, Filter};
use vanguard::egress::Verdict;

fn config_with(allow: &str) -> Config {
    Config::from_toml(&format!("[egress]\nallow = [{allow}]\n")).unwrap()
}

#[test]
fn config_rules_reach_the_policy() {
    let policy = config_with(r#""*.example.com", "10.0.0.0/8""#)
        .egress_policy()
        .unwrap();
    assert_eq!(policy.entries().len(), 2);
    assert!(policy.decide("api.example.com", 443).is_allowed());
    assert!(policy.decide("10.1.2.3", 5432).is_allowed());
    assert_eq!(policy.decide("elsewhere.test", 443), Verdict::Deny);
}

#[test]
fn the_default_config_denies_everything() {
    // The safe posture, and the one a fresh install gets.
    let policy = Config::default().egress_policy().unwrap();
    assert!(policy.is_empty());
    assert_eq!(policy.decide("anywhere.test", 443), Verdict::Deny);
    assert_eq!(policy.decide("127.0.0.1", 80), Verdict::Deny);
}

#[test]
fn a_malformed_rule_stops_the_config_rather_than_being_dropped() {
    // A silently ignored rule leaves the config file describing an enforcement
    // that is not happening, which is the worst of both.
    let err = config_with(r#""10.0.0.0/33""#).egress_policy().unwrap_err();
    assert!(err.to_string().contains("10.0.0.0/33"), "{err}");
}

#[test]
fn there_is_no_way_to_write_allow_everything() {
    assert!(config_with(r#""*""#).egress_policy().is_err());
}

#[test]
fn hostname_rules_are_reported_as_unenforceable_at_the_socket_layer() {
    // The honesty requirement. A filter that quietly ignored these would leave
    // an operator believing `*.example.com` is enforced by the kernel.
    let policy = config_with(r#""*.example.com", "10.0.0.0/8", "one.test""#)
        .egress_policy()
        .unwrap();
    let (enforceable, skipped) = filter::triage(&policy);

    assert_eq!(enforceable, 1);
    assert_eq!(
        skipped.iter().map(|s| s.rule.as_str()).collect::<Vec<_>>(),
        vec!["*.example.com", "one.test"]
    );
}

#[test]
fn attaching_never_silently_succeeds_where_it_cannot_work() {
    // "Falling back to permissive networking" is in the risk taxonomy for a
    // reason: the only safe failure here is a loud one.
    if Filter::available() {
        return;
    }
    let policy = config_with(r#""10.0.0.0/8""#).egress_policy().unwrap();
    let err = Filter::attach(&policy, std::path::Path::new("/sys/fs/cgroup"), false).unwrap_err();
    let message = err.to_string();
    assert!(message.contains("Nothing was attached"), "{message}");
    assert!(message.contains("ebpf"), "{message}");
}

#[test]
fn a_policy_of_names_only_is_enforceable_nowhere_at_the_socket_layer() {
    let policy = config_with(r#""*.example.com""#).egress_policy().unwrap();
    let (enforceable, skipped) = filter::triage(&policy);
    assert_eq!(enforceable, 0);
    assert_eq!(skipped.len(), 1);
}
