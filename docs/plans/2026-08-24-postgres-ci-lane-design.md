# PostgreSQL CI Lane Design

## Goal

Add a dedicated CI lane that discovers every PostgreSQL-only test by convention, runs each test against an isolated database, and deliberately exercises both the committed desired-state schema and the embedded migration path.

## Scope

This change is limited to test organization and CI harness code. It does not move production database code, introduce shared production test utilities, or change persistence semantics. Existing infrastructure-free unit-test commands remain unchanged.

## Discovery convention

PostgreSQL-only tests must be ignored and live under a module named `postgres_tests`, or in an integration-test binary whose name starts `postgres_`. Tests that additionally require external infrastructure such as S3 or MinIO use an `external_infra_` test-name prefix and are excluded from this lane.

The nextest profile owns this structural filter. Future PostgreSQL tests join the lane by following the naming convention; CI does not maintain a list of test names.

## Database lifecycle

A bounded run script owns a desired-state source database built from `schema/schema.sql` with partition tables attached, and removes it on exit. A per-test nextest wrapper creates a uniquely named database and points all supported database URL variables at it. Ordinary tests clone the desired-state source database.

Tests under `migration::postgres_tests` and tests with a
`migration_schema_` function-name prefix receive an empty database cloned
from `template0`; those tests apply embedded migrations themselves. This
keeps migration-applied and desired-state coverage intentional and prevents
migrations from being reapplied to an already materialized desired-state schema.

The wrapper force-drops the database after the test while preserving the test exit status. Names derive from the nextest run, test, and attempt identifiers so parallel execution and retries cannot collide.

## CI shape

A dedicated nextest archive compiles every library and integration-test target across the PostgreSQL-backed crates, so future structurally named tests are packaged automatically. A dedicated PostgreSQL job starts PostgreSQL 16, runs the setup script, and invokes the structural nextest profile with ignored tests enabled. The exact four-test selector introduced by the parent PR is removed because those tests are covered by the complete lane.

## Risks

The convention is enforced by documentation and CI selection rather than a Rust attribute macro. Hybrid PostgreSQL-plus-external-infrastructure tests remain outside this lane and retain their existing specialized coverage.
