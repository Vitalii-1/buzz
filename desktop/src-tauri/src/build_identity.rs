//! Compile-time identity for reusable named demo builds.
//!
//! Production builds leave `BUZZ_DESKTOP_BUILD_DEMO_SLUG` unset and retain all
//! existing names. The demo recipe validates one slug and `build.rs` bakes it
//! into the binary; every runtime identity is then derived from that one value.

use std::borrow::Cow;

pub(crate) fn demo_slug() -> Option<&'static str> {
    option_env!("BUZZ_DESKTOP_BUILD_DEMO_SLUG")
}

pub(crate) fn is_demo_build() -> bool {
    demo_slug().is_some()
}

pub(crate) fn demo_config_home() -> Option<std::path::PathBuf> {
    demo_config_home_for(demo_slug(), dirs::config_dir())
}

/// Keep child config caches inside this demo build's identity. In particular,
/// bundled buzz-agent OAuth tokens must not read or write production's root.
pub(crate) fn apply_demo_config_home(command: &mut std::process::Command) {
    if let Some(config_home) = demo_config_home() {
        command.env("XDG_CONFIG_HOME", config_home);
    }
}

fn demo_config_home_for(
    demo_slug: Option<&str>,
    config_dir: Option<std::path::PathBuf>,
) -> Option<std::path::PathBuf> {
    demo_slug
        .zip(config_dir)
        .map(|(slug, dir)| dir.join(format!("buzz-demo-{slug}")))
}

pub(crate) fn deep_link_scheme() -> Cow<'static, str> {
    demo_slug()
        .map(|slug| Cow::Owned(format!("buzz-demo-{slug}")))
        .unwrap_or(Cow::Borrowed("buzz"))
}

pub(crate) fn is_deep_link_for_build(value: &str) -> bool {
    is_deep_link_for_scheme(value, deep_link_scheme().as_ref())
}

fn is_deep_link_for_scheme(value: &str, scheme: &str) -> bool {
    value
        .strip_prefix(scheme)
        .is_some_and(|suffix| suffix.starts_with("://"))
}

pub(crate) fn keyring_service() -> Cow<'static, str> {
    demo_slug()
        .map(|slug| Cow::Owned(format!("buzz-desktop-demo.{slug}")))
        .unwrap_or(Cow::Borrowed("buzz-desktop"))
}

pub(crate) fn nest_name(is_dev: bool) -> Cow<'static, str> {
    nest_name_for(demo_slug(), is_dev)
}

fn nest_name_for(demo_slug: Option<&str>, is_dev: bool) -> Cow<'_, str> {
    if let Some(slug) = demo_slug {
        Cow::Owned(format!(".buzz-demo-{slug}"))
    } else if is_dev {
        Cow::Borrowed(".buzz-dev")
    } else {
        Cow::Borrowed(".buzz")
    }
}

pub(crate) fn cli_name(is_dev: bool) -> String {
    if let Some(slug) = demo_slug() {
        format!("buzz-demo-{slug}")
    } else if is_dev {
        "buzz-dev".to_string()
    } else {
        "buzz".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_release_defaults_remain_production_identity() {
        if demo_slug().is_none() {
            assert_eq!(deep_link_scheme(), "buzz");
            assert_eq!(keyring_service(), "buzz-desktop");
            assert_eq!(nest_name(false), ".buzz");
            assert_eq!(cli_name(false), "buzz");
        }
    }

    #[test]
    fn demo_agent_config_home_is_build_scoped() {
        let base = std::path::PathBuf::from("/config");
        assert_eq!(demo_config_home_for(None, Some(base.clone())), None);
        assert_eq!(
            demo_config_home_for(Some("board-1234567812345678"), Some(base)),
            Some(std::path::PathBuf::from(
                "/config/buzz-demo-board-1234567812345678"
            ))
        );
    }

    #[test]
    fn duplicate_instance_links_follow_the_build_scheme() {
        assert!(is_deep_link_for_scheme("buzz://message?id=1", "buzz"));
        assert!(!is_deep_link_for_scheme(
            "buzz-demo-board-1234567812345678://message?id=1",
            "buzz"
        ));
        assert!(is_deep_link_for_scheme(
            "buzz-demo-board-1234567812345678://message?id=1",
            "buzz-demo-board-1234567812345678"
        ));
        assert!(!is_deep_link_for_scheme(
            "buzz://message?id=1",
            "buzz-demo-board-1234567812345678"
        ));
    }

    #[test]
    fn production_and_named_demo_nests_are_distinct() {
        assert_eq!(nest_name_for(None, false), ".buzz");
        assert_eq!(
            nest_name_for(Some("workstream-board"), false),
            ".buzz-demo-workstream-board"
        );
        assert_eq!(
            nest_name_for(Some("second-demo"), false),
            ".buzz-demo-second-demo"
        );
    }
}
