# PostgreSQL CI Lane Implementation Plan

> **For Codex:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task.

**Goal:** Add an automatically discovered, parallel-safe PostgreSQL test lane covering desired-state and migration-applied schemas.

**Architecture:** Nextest discovers ignored PostgreSQL tests through structural module and binary names. A bounded runner owns and removes a desired-state source database, while a per-test wrapper creates and deletes one database per test and selects the proper schema bootstrap mode.

**Tech Stack:** Rust, cargo-nextest, PostgreSQL 16, Bash, GitHub Actions.

---

### Task 1: Establish the failing baseline

1. Run the broad ignored `buzz-db` suite against one desired-state database.
2. Record total, passing, and failing counts plus representative failure causes.

### Task 2: Define automatic discovery

**Files:** Modify PostgreSQL test modules in `crates/*`, rename `crates/buzz-search/tests/fts_integration.rs`, modify `.config/nextest.toml` and `CONTRIBUTING.md`.

1. Rename PostgreSQL-backed test modules to `postgres_tests`.
2. Give hybrid S3/MinIO tests an `external_infra_` test-name prefix or keep them outside the structural PostgreSQL convention.
3. Rename the search integration binary with a `postgres_` prefix.
4. Add a nextest profile filter based on those structural names.
5. Document the convention and schema modes.

### Task 3: Add isolated database lifecycle

**Files:** Create `scripts/postgres-test-setup.sh` and `scripts/postgres-test-wrapper.sh`; modify only test connection helpers that hard-code the shared URL.

1. Create one desired-state source database per nextest run and remove it when the runner exits.
2. Create a unique database per test and attempt.
3. Select desired-state or empty migration-owned bootstrap by test path.
4. Export all database URL variables used by the suites.
5. Always force-drop the isolated database and preserve the test status.

### Task 4: Wire the CI lane

**Files:** Modify `.github/workflows/ci.yml`.

1. Build a dedicated archive with all library and integration-test targets from the intended PostgreSQL-backed crates.
2. Add a PostgreSQL 16 job running the dedicated nextest profile.
3. Remove the parent's exact four-test selector.
4. Leave infrastructure-free unit jobs unchanged.

### Task 5: Verify on Blox

1. Run shell syntax and nextest discovery checks.
2. Run formatting and linting.
3. Run the four parent-PR persistence tests through the lane.
4. Run the complete lane with parallel execution.
5. Report exact discovered, run, skipped, passed, and failed counts.

### Task 6: Publish and independently review

1. Transfer the verified patch to a clean local clone and review it.
2. Push locally and open a stacked draft PR.
3. Verify the actual GitHub PostgreSQL lane.
4. Review the exact PR head on a separate Blox workstation.
5. Address substantive findings, rerun verification, and report remaining risks.
