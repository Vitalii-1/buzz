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

pub(crate) fn deep_link_scheme() -> Cow<'static, str> {
    demo_slug()
        .map(|slug| Cow::Owned(format!("buzz-demo-{slug}")))
        .unwrap_or(Cow::Borrowed("buzz"))
}

pub(crate) fn keyring_service() -> Cow<'static, str> {
    demo_slug()
        .map(|slug| Cow::Owned(format!("buzz-desktop-demo.{slug}")))
        .unwrap_or(Cow::Borrowed("buzz-desktop"))
}

pub(crate) fn nest_name(is_dev: bool) -> Cow<'static, str> {
    if let Some(slug) = demo_slug() {
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
}
