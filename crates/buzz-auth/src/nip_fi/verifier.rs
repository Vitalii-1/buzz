//! The single provider-neutral assertion verifier (`FI-INV-16`).
//!
//! Every accepted compact JWS feeds this one contract and produces a sealed
//! [`VerifiedAssertion`]. Multi-issuer selection happens here: the exact `iss`
//! carried by the token selects one [`IssuerPolicy`] and its key source; there
//! is no single-global-issuer assumption. All failures collapse to the public
//! [`DenialClass::EvidenceRejected`] class; the granular
//! [`VerifierError`] variants are for access-controlled logs and metrics only.
//!
//! Corrections applied to the mined #1476 verifier, per the settled spec:
//!
//! - **Token class + `typ` enforcement**: a policy selects exactly one class
//!   before parsing claims; `at+jwt`, `nip-fi+jwt`, and named-compatibility
//!   `typ` values are enforced exactly, and the long-form `application/at+jwt`
//!   is rejected.
//! - **ID-token denial**: OIDC ID tokens deny even when `iss`, `aud`, `sub`
//!   match, via `typ` mismatch and forbidden-claim exclusion.
//! - **Fixed `nostr_pubkey`**: accepted only as lowercase hex of exactly one
//!   32-byte key; bech32 and other aliases deny.
//! - **Spec-exact time arithmetic**: `now < exp`, `iat <= now + skew`,
//!   `now < iat + maximum_assertion_age`, `nbf <= now + skew`, equality at an
//!   expiry is expired.

use super::assertion::{CanonicalCapabilities, RevalidationDependencies, VerifiedAssertion};
use super::config::{
    is_asymmetric_algorithm, FreshnessClass, IssuerPolicy, IssuerRegistry, TokenClass,
    TransportContractId, NOSTR_PUBKEY_CLAIM,
};
use super::denial::DenialClass;
use chrono::{DateTime, TimeZone, Utc};
use jsonwebtoken::jwk::{JwkSet, KeyAlgorithm, PublicKeyUse};
use jsonwebtoken::{decode, jwk::Jwk, Algorithm, DecodingKey, Validation};
use nostr::PublicKey;
use serde_json::{Map, Value};
use std::fmt;

/// Maximum accepted compact-JWS length, in bytes.
const MAX_TOKEN_BYTES: usize = 64 * 1024;
/// Maximum accepted `kid` length, in bytes.
const MAX_KID_BYTES: usize = 512;
/// Maximum accepted subject length, in bytes.
const MAX_SUBJECT_BYTES: usize = 2_048;
/// Maximum accepted `client_id` length, in bytes.
const MAX_CLIENT_ID_BYTES: usize = 2_048;

/// One issuer's key source: a JWKS snapshot with a positive generation and an
/// optional hard deadline beyond which the snapshot can no longer authorize.
#[derive(Clone)]
pub struct AssertionKeySet {
    generation: u64,
    jwks: JwkSet,
    hard_deadline: Option<DateTime<Utc>>,
}

impl AssertionKeySet {
    /// Seal a parsed JWKS with a positive cache generation and optional deadline.
    /// A zero generation is rejected.
    pub fn new(
        generation: u64,
        jwks: JwkSet,
        hard_deadline: Option<DateTime<Utc>>,
    ) -> Option<Self> {
        if generation == 0 {
            return None;
        }
        Some(Self {
            generation,
            jwks,
            hard_deadline,
        })
    }

    /// The positive snapshot generation carried into `revalidation_dependencies`.
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

impl fmt::Debug for AssertionKeySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AssertionKeySet([REDACTED])")
    }
}

/// The provider-neutral assertion verifier over a closed multi-issuer registry.
#[derive(Debug, Clone)]
pub struct FederatedAssertionVerifier {
    registry: IssuerRegistry,
    transport_contract_id: TransportContractId,
}

impl FederatedAssertionVerifier {
    /// Construct a verifier over a registry of issuer policies.
    pub fn new(registry: IssuerRegistry) -> Self {
        Self {
            registry,
            transport_contract_id: TransportContractId::core_client_attached(),
        }
    }

    /// The registry this verifier selects policies from.
    pub const fn registry(&self) -> &IssuerRegistry {
        &self.registry
    }

    /// Verify one compact JWS and mint a sealed [`VerifiedAssertion`].
    ///
    /// `key_set` is the key source for the token's issuer, selected by the
    /// caller after [`Self::issuer_of`] or supplied as a per-issuer snapshot.
    /// The issuer is re-selected and re-checked here against the registry and
    /// the token's signed `iss`.
    pub fn verify(
        &self,
        token: &str,
        key_set: &AssertionKeySet,
    ) -> Result<VerifiedAssertion, VerifierError> {
        if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
            return Err(VerifierError::MalformedToken);
        }

        // Parse the JOSE header without trusting it. Reject `alg=none`,
        // symmetric algorithms, any critical header, and a missing/oversized
        // `kid` before touching claims.
        let header = parse_header(token)?;
        let policy = self
            .registry
            .policy_for_issuer(&self.unverified_issuer(token)?)
            .ok_or(VerifierError::UnknownIssuer)?;

        if !policy.algorithms().contains(&header.algorithm) {
            return Err(VerifierError::UnsupportedAlgorithm);
        }
        enforce_token_type(policy.token_class(), header.typ.as_deref())?;

        // Select exactly one matching key by `kid`.
        let jwk = select_unique_jwk(&key_set.jwks, &header.kid)?;
        validate_jwk(jwk, header.algorithm)?;
        let key = DecodingKey::from_jwk(jwk).map_err(|_| VerifierError::InvalidKey)?;

        // Verify signature, `iss`, and `aud` only. All time checks are done
        // manually below for spec-exact arithmetic.
        let mut validation = Validation::new(header.algorithm);
        validation.set_issuer(&[policy.issuer()]);
        validation.set_audience(policy.audiences());
        validation.set_required_spec_claims(&["exp", "iat", "iss", "aud"]);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        let decoded = decode::<Map<String, Value>>(token, &key, &validation)
            .map_err(|_| VerifierError::InvalidSignatureOrClaims)?;
        let claims = &decoded.claims;

        enforce_claim_semantics(policy, claims)?;

        let subject = claim_string(claims, policy.subject_claim(), MAX_SUBJECT_BYTES)?;
        let asserted_key = parse_nostr_pubkey_claim(policy, claims)?;

        let now = Utc::now();
        let deadlines = self.check_time_and_deadlines(policy, key_set, claims, now)?;
        let capabilities = capture_capabilities(policy, claims);

        Ok(VerifiedAssertion::seal(
            policy.issuer().to_owned(),
            subject,
            asserted_key,
            capabilities,
            deadlines,
            policy.id(),
            self.transport_contract_id,
            RevalidationDependencies::new(header.kid, key_set.generation()),
        ))
    }

    /// The exact `iss` carried by a token, read without verifying its
    /// signature. Used only to select a policy; the signed `iss` is
    /// re-validated by [`Self::verify`].
    pub fn issuer_of(&self, token: &str) -> Result<String, VerifierError> {
        self.unverified_issuer(token)
    }

    fn unverified_issuer(&self, token: &str) -> Result<String, VerifierError> {
        let claims = decode_claims_segment(token)?;
        claim_string(&claims, "iss", MAX_SUBJECT_BYTES).map_err(|_| VerifierError::MalformedToken)
    }

    fn check_time_and_deadlines(
        &self,
        policy: &IssuerPolicy,
        key_set: &AssertionKeySet,
        claims: &Map<String, Value>,
        now: DateTime<Utc>,
    ) -> Result<Vec<DateTime<Utc>>, VerifierError> {
        let iat = numeric_date(claims, "iat")?;
        let exp = numeric_date(claims, "exp")?;
        let skew = seconds(policy.skew_seconds());
        let max_age = seconds(policy.maximum_assertion_age_seconds());

        // now < exp (equality is expired).
        if now >= exp {
            return Err(VerifierError::Expired);
        }
        // iat <= now + skew.
        if iat > checked_add(now, skew)? {
            return Err(VerifierError::NotYetValid);
        }
        // now < iat + maximum_assertion_age.
        if now >= checked_add(iat, max_age)? {
            return Err(VerifierError::Expired);
        }
        // Optional nbf <= now + skew.
        if let Some(nbf) = optional_numeric_date(claims, "nbf")? {
            if nbf > checked_add(now, skew)? {
                return Err(VerifierError::NotYetValid);
            }
        }

        // offline authority deadline = min(exp, iat + max_age, key hard deadline).
        let mut deadlines = vec![exp, checked_add(iat, max_age)?];
        if let Some(hard) = key_set.hard_deadline {
            if now >= hard {
                return Err(VerifierError::Expired);
            }
            deadlines.push(hard);
        }
        // `current-status` adds a runtime status deadline in a later PR; the
        // offline deadlines computed here always bound it.
        debug_assert!(matches!(
            policy.freshness(),
            FreshnessClass::OfflineJwt | FreshnessClass::CurrentStatus
        ));
        Ok(deadlines)
    }
}

/// A closed, stable verifier failure carrying no credential material. Every
/// variant maps to the public [`DenialClass::EvidenceRejected`] class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VerifierError {
    /// The compact JWS was empty, oversized, or structurally malformed.
    #[error("malformed token")]
    MalformedToken,
    /// No policy is registered for the token's issuer.
    #[error("unknown issuer")]
    UnknownIssuer,
    /// The header algorithm is `none`, symmetric, or outside the policy set.
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,
    /// The header carried a critical extension this verifier does not support.
    #[error("unsupported critical header")]
    UnsupportedCriticalHeader,
    /// The header omitted its bounded `kid`.
    #[error("missing key id")]
    MissingKeyId,
    /// No key, or more than one key, matched the header `kid`.
    #[error("ambiguous or unknown key id")]
    AmbiguousKeyId,
    /// The selected JWK was not admissible for signature verification.
    #[error("invalid key")]
    InvalidKey,
    /// The `typ` header did not match the policy's token class.
    #[error("token type rejected")]
    TokenTypeRejected,
    /// A required or forbidden claim rule for the token class failed, including
    /// resource-owner/client-subject ambiguity.
    #[error("claim contract rejected")]
    ClaimContractRejected,
    /// A required provider-free claim was missing or malformed, including a
    /// `nostr_pubkey` that was not lowercase-hex of one 32-byte key.
    #[error("claim rejected")]
    ClaimRejected,
    /// The signature, issuer, or audience did not validate.
    #[error("signature or claims rejected")]
    InvalidSignatureOrClaims,
    /// The assertion was expired or beyond its maximum age or key deadline.
    #[error("expired")]
    Expired,
    /// The assertion was not yet valid under `iat`/`nbf` and skew.
    #[error("not yet valid")]
    NotYetValid,
    /// A time claim was missing, non-integer, or arithmetically out of range.
    #[error("invalid time bounds")]
    InvalidTimeBounds,
}

impl VerifierError {
    /// The public denial class. Every verifier failure is evidence rejection:
    /// malformed, invalid, or expired evidence.
    pub const fn denial_class(self) -> DenialClass {
        DenialClass::EvidenceRejected
    }

    /// A unique stable machine code, safe for access-controlled logs.
    pub const fn code(self) -> &'static str {
        match self {
            Self::MalformedToken => "nip_fi_malformed_token",
            Self::UnknownIssuer => "nip_fi_unknown_issuer",
            Self::UnsupportedAlgorithm => "nip_fi_unsupported_algorithm",
            Self::UnsupportedCriticalHeader => "nip_fi_unsupported_critical_header",
            Self::MissingKeyId => "nip_fi_missing_key_id",
            Self::AmbiguousKeyId => "nip_fi_ambiguous_key_id",
            Self::InvalidKey => "nip_fi_invalid_key",
            Self::TokenTypeRejected => "nip_fi_token_type_rejected",
            Self::ClaimContractRejected => "nip_fi_claim_contract_rejected",
            Self::ClaimRejected => "nip_fi_claim_rejected",
            Self::InvalidSignatureOrClaims => "nip_fi_invalid_signature_or_claims",
            Self::Expired => "nip_fi_expired",
            Self::NotYetValid => "nip_fi_not_yet_valid",
            Self::InvalidTimeBounds => "nip_fi_invalid_time_bounds",
        }
    }
}

/// A minimally parsed JOSE header.
struct ParsedHeader {
    algorithm: Algorithm,
    kid: String,
    typ: Option<String>,
}

fn parse_header(token: &str) -> Result<ParsedHeader, VerifierError> {
    let segment = token
        .split('.')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or(VerifierError::MalformedToken)?;
    let bytes = base64url_decode(segment)?;
    let header: Map<String, Value> =
        serde_json::from_slice(&bytes).map_err(|_| VerifierError::MalformedToken)?;

    // Any critical extension is unknown to this verifier and denies.
    if header.contains_key("crit") {
        return Err(VerifierError::UnsupportedCriticalHeader);
    }

    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or(VerifierError::MalformedToken)?;
    let algorithm = parse_algorithm(alg)?;
    if !is_asymmetric_algorithm(algorithm) {
        return Err(VerifierError::UnsupportedAlgorithm);
    }

    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .filter(|k| !k.is_empty() && k.len() <= MAX_KID_BYTES)
        .ok_or(VerifierError::MissingKeyId)?
        .to_owned();

    let typ = match header.get("typ") {
        None => None,
        Some(Value::String(s)) => Some(s.clone()),
        // A present but non-string `typ` is malformed.
        Some(_) => return Err(VerifierError::MalformedToken),
    };

    Ok(ParsedHeader {
        algorithm,
        kid,
        typ,
    })
}

fn parse_algorithm(alg: &str) -> Result<Algorithm, VerifierError> {
    match alg {
        "RS256" => Ok(Algorithm::RS256),
        "RS384" => Ok(Algorithm::RS384),
        "RS512" => Ok(Algorithm::RS512),
        "PS256" => Ok(Algorithm::PS256),
        "PS384" => Ok(Algorithm::PS384),
        "PS512" => Ok(Algorithm::PS512),
        "ES256" => Ok(Algorithm::ES256),
        "ES384" => Ok(Algorithm::ES384),
        "EdDSA" => Ok(Algorithm::EdDSA),
        // `none` and symmetric HMAC algorithms are rejected as unsupported.
        "none" | "HS256" | "HS384" | "HS512" => Err(VerifierError::UnsupportedAlgorithm),
        _ => Err(VerifierError::UnsupportedAlgorithm),
    }
}

/// Enforce the policy's single token class against the header `typ`.
fn enforce_token_type(class: &TokenClass, typ: Option<&str>) -> Result<(), VerifierError> {
    match class {
        TokenClass::AccessTokenAtJwt => match typ {
            Some("at+jwt") => Ok(()),
            _ => Err(VerifierError::TokenTypeRejected),
        },
        TokenClass::DedicatedNipFi => match typ {
            Some("nip-fi+jwt") => Ok(()),
            _ => Err(VerifierError::TokenTypeRejected),
        },
        TokenClass::NamedCompatibility { .. } => match typ {
            None | Some("JWT") => Ok(()),
            _ => Err(VerifierError::TokenTypeRejected),
        },
    }
}

/// Enforce class-specific claim rules: `at+jwt` `client_id` presence and
/// resource-owner/client-subject exclusivity, and named-compatibility
/// required/forbidden claims (which exclude OIDC ID tokens).
fn enforce_claim_semantics(
    policy: &IssuerPolicy,
    claims: &Map<String, Value>,
) -> Result<(), VerifierError> {
    match policy.token_class() {
        TokenClass::AccessTokenAtJwt => {
            let client_id = claims
                .get("client_id")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|c| !c.is_empty() && c.len() <= MAX_CLIENT_ID_BYTES)
                .ok_or(VerifierError::ClaimContractRejected)?;
            // A token whose subject equals its client id is a client-subject
            // token and is ineligible under a resource-owner policy: it admits
            // both interpretations, so it denies.
            let subject = claims.get(policy.subject_claim()).and_then(Value::as_str);
            if subject == Some(client_id) {
                return Err(VerifierError::ClaimContractRejected);
            }
            Ok(())
        }
        TokenClass::DedicatedNipFi => Ok(()),
        TokenClass::NamedCompatibility {
            required_claims,
            forbidden_claims,
        } => {
            if required_claims.iter().any(|c| !claims.contains_key(c))
                || forbidden_claims.iter().any(|c| claims.contains_key(c))
            {
                return Err(VerifierError::ClaimContractRejected);
            }
            Ok(())
        }
    }
}

/// Parse the fixed `nostr_pubkey` claim: lowercase hex of exactly one 32-byte
/// key. Bech32 and other aliases deny. Absence is permitted unless the policy
/// requires an attested key.
fn parse_nostr_pubkey_claim(
    policy: &IssuerPolicy,
    claims: &Map<String, Value>,
) -> Result<Option<PublicKey>, VerifierError> {
    match claims.get(NOSTR_PUBKEY_CLAIM) {
        None => {
            if policy.require_attested_key() {
                Err(VerifierError::ClaimRejected)
            } else {
                Ok(None)
            }
        }
        Some(value) => {
            let raw = value.as_str().ok_or(VerifierError::ClaimRejected)?;
            if raw.len() != 64
                || !raw
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(VerifierError::ClaimRejected);
            }
            let key = PublicKey::from_hex(raw).map_err(|_| VerifierError::ClaimRejected)?;
            Ok(Some(key))
        }
    }
}

/// Capture only the claim names the policy reads into a canonical set. For PR 1
/// the closed set is the `scope` claim, split on ASCII space; unchecked claims
/// never enter the result.
fn capture_capabilities(
    _policy: &IssuerPolicy,
    claims: &Map<String, Value>,
) -> CanonicalCapabilities {
    let mut entries = Vec::new();
    if let Some(scope) = claims.get("scope").and_then(Value::as_str) {
        for token in scope.split(' ').filter(|s| !s.is_empty()) {
            entries.push(("scope".to_owned(), token.to_owned()));
        }
    }
    CanonicalCapabilities::from_sorted(entries)
}

fn select_unique_jwk<'a>(jwks: &'a JwkSet, kid: &str) -> Result<&'a Jwk, VerifierError> {
    let mut matching = jwks
        .keys
        .iter()
        .filter(|jwk| jwk.common.key_id.as_deref() == Some(kid));
    let jwk = matching.next().ok_or(VerifierError::AmbiguousKeyId)?;
    if matching.next().is_some() {
        return Err(VerifierError::AmbiguousKeyId);
    }
    Ok(jwk)
}

fn validate_jwk(jwk: &Jwk, token_algorithm: Algorithm) -> Result<(), VerifierError> {
    let usage_ok = jwk
        .common
        .public_key_use
        .as_ref()
        .is_none_or(|use_| use_ == &PublicKeyUse::Signature);
    let algorithm_ok = jwk
        .common
        .key_algorithm
        .is_none_or(|alg| jwk_algorithm_matches(alg, token_algorithm));
    if usage_ok && algorithm_ok {
        Ok(())
    } else {
        Err(VerifierError::InvalidKey)
    }
}

fn jwk_algorithm_matches(key: KeyAlgorithm, token: Algorithm) -> bool {
    matches!(
        (key, token),
        (KeyAlgorithm::RS256, Algorithm::RS256)
            | (KeyAlgorithm::RS384, Algorithm::RS384)
            | (KeyAlgorithm::RS512, Algorithm::RS512)
            | (KeyAlgorithm::PS256, Algorithm::PS256)
            | (KeyAlgorithm::PS384, Algorithm::PS384)
            | (KeyAlgorithm::PS512, Algorithm::PS512)
            | (KeyAlgorithm::ES256, Algorithm::ES256)
            | (KeyAlgorithm::ES384, Algorithm::ES384)
            | (KeyAlgorithm::EdDSA, Algorithm::EdDSA)
    )
}

fn claim_string(
    claims: &Map<String, Value>,
    claim: &str,
    max_len: usize,
) -> Result<String, VerifierError> {
    claims
        .get(claim)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty() && v.len() <= max_len)
        .map(str::to_owned)
        .ok_or(VerifierError::ClaimRejected)
}

fn numeric_date(claims: &Map<String, Value>, claim: &str) -> Result<DateTime<Utc>, VerifierError> {
    let secs = claims
        .get(claim)
        .and_then(Value::as_i64)
        .ok_or(VerifierError::InvalidTimeBounds)?;
    Utc.timestamp_opt(secs, 0)
        .single()
        .ok_or(VerifierError::InvalidTimeBounds)
}

fn optional_numeric_date(
    claims: &Map<String, Value>,
    claim: &str,
) -> Result<Option<DateTime<Utc>>, VerifierError> {
    match claims.get(claim) {
        None => Ok(None),
        Some(value) => {
            let secs = value.as_i64().ok_or(VerifierError::InvalidTimeBounds)?;
            Utc.timestamp_opt(secs, 0)
                .single()
                .map(Some)
                .ok_or(VerifierError::InvalidTimeBounds)
        }
    }
}

fn seconds(value: u64) -> chrono::Duration {
    chrono::Duration::seconds(value as i64)
}

fn checked_add(at: DateTime<Utc>, delta: chrono::Duration) -> Result<DateTime<Utc>, VerifierError> {
    at.checked_add_signed(delta)
        .ok_or(VerifierError::InvalidTimeBounds)
}

fn decode_claims_segment(token: &str) -> Result<Map<String, Value>, VerifierError> {
    let segment = token
        .split('.')
        .nth(1)
        .filter(|s| !s.is_empty())
        .ok_or(VerifierError::MalformedToken)?;
    let bytes = base64url_decode(segment)?;
    serde_json::from_slice(&bytes).map_err(|_| VerifierError::MalformedToken)
}

fn base64url_decode(segment: &str) -> Result<Vec<u8>, VerifierError> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| VerifierError::MalformedToken)
}
