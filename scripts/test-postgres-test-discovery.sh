#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checker="$repo_root/scripts/check-postgres-test-discovery.py"
fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/buzz-postgres-discovery.XXXXXX")"
trap 'rm -rf "$fixture_root"' EXIT

mkdir -p "$fixture_root/src/tests" "$fixture_root/tests/common"

cat >"$fixture_root/Cargo.toml" <<'TOML'
[package]
name = "postgres-discovery-fixture"
version = "0.0.0"
edition = "2021"
TOML

cat >"$fixture_root/src/good.rs" <<'RS'
#[cfg(test)]
mod postgres_tests {
    #[test]
    #[ignore = "requires Postgres"]
    fn ordinary_database_test() {}

    mod external_infra_tests {
        #[tokio::test]
        #[ignore = "requires Postgres and S3-compatible storage"]
        async fn hybrid_database_test() {}
    }
}
RS

cat >"$fixture_root/tests/postgres_search.rs" <<'RS'
#[test]
#[ignore = "requires PostgreSQL"]
fn integration_database_test() {}
RS

python3 "$checker" "$fixture_root"

packages="$("$repo_root/scripts/postgres-test-packages.sh" "$fixture_root")"
if [[ "$packages" != "postgres-discovery-fixture" ]]; then
  echo "expected fixture package discovery, got: $packages" >&2
  exit 1
fi

cat >"$fixture_root/src/tests/postgres_nested.rs" <<'RS'
#[test]
#[ignore = "requires PostgreSQL"]
fn nested_source_module_is_not_an_integration_binary() {}
RS

cat >"$fixture_root/tests/common/postgres_helper.rs" <<'RS'
#[test]
#[ignore = "requires PostgreSQL"]
fn nested_integration_helper_is_not_an_integration_binary() {}
RS

if python3 "$checker" "$fixture_root" >"$fixture_root/nested.out" 2>&1; then
  echo "expected nested postgres_* modules to fail discovery validation" >&2
  exit 1
fi
grep -q "nested_source_module_is_not_an_integration_binary" "$fixture_root/nested.out"
grep -q "nested_integration_helper_is_not_an_integration_binary" "$fixture_root/nested.out"
rm "$fixture_root/src/tests/postgres_nested.rs"
rm "$fixture_root/tests/common/postgres_helper.rs"

cat >"$fixture_root/src/missed.rs" <<'RS'
#[cfg(test)]
mod tests {
    #[test]
    #[ignore = "requires Postgres"]
    fn silently_missed_database_test() {}
}
RS

if python3 "$checker" "$fixture_root" >"$fixture_root/missed.out" 2>&1; then
  echo "expected an unclassified PostgreSQL test to fail discovery validation" >&2
  exit 1
fi
grep -q "silently_missed_database_test" "$fixture_root/missed.out"
rm "$fixture_root/src/missed.rs"

cat >"$fixture_root/src/raw_missed.rs" <<'RS'
#[cfg(test)]
mod tests {
    #[test]
    #[ignore = r#"requires PostgreSQL"#]
    fn raw_string_database_test() {}
}
RS

if python3 "$checker" "$fixture_root" >"$fixture_root/raw-missed.out" 2>&1; then
  echo "expected a raw-string PostgreSQL reason to fail discovery validation" >&2
  exit 1
fi
grep -q "raw_string_database_test" "$fixture_root/raw-missed.out"
rm "$fixture_root/src/raw_missed.rs"

cat >"$fixture_root/src/commented.rs" <<'RS'
#[cfg(test)]
mod tests {
    // #[ignore = "requires Postgres"]
    fn ordinary_helper() {}
}
RS

python3 "$checker" "$fixture_root"
rm "$fixture_root/src/commented.rs"

cat >"$fixture_root/src/hybrid.rs" <<'RS'
#[cfg(test)]
mod postgres_tests {
    #[test]
    #[ignore = "requires Postgres and MinIO"]
    fn hybrid_without_external_module() {}
}
RS

if python3 "$checker" "$fixture_root" >"$fixture_root/hybrid.out" 2>&1; then
  echo "expected a hybrid test without an external-infra module to fail validation" >&2
  exit 1
fi
grep -q "hybrid_without_external_module" "$fixture_root/hybrid.out"
rm "$fixture_root/src/hybrid.rs"

cat >"$fixture_root/src/name_is_not_classification.rs" <<'RS'
#[cfg(test)]
mod postgres_tests {
    #[test]
    #[ignore = "requires Postgres and MinIO"]
    fn external_infra_prefix_is_not_enough() {}
}
RS

if python3 "$checker" "$fixture_root" >"$fixture_root/name.out" 2>&1; then
  echo "expected function-name infrastructure classification to fail validation" >&2
  exit 1
fi
grep -q "external_infra_prefix_is_not_enough" "$fixture_root/name.out"
rm "$fixture_root/src/name_is_not_classification.rs"

python3 "$checker" "$repo_root/crates"

echo "PostgreSQL test discovery convention checks passed"
