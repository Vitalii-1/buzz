//! Multi-issuer assertion-policy configuration and the two NIP-FI semantic
//! contract identities.
//!
//! Identity is issuer-qualified `(iss, sub)`; there is no single-global-issuer
//! assumption. An [`IssuerRegistry`] selects exactly one [`IssuerPolicy`] by the
//! exact `iss` value returned by JWT decoding. Block V1 enables one issuer via
//! deployment config, but the contract admits any number.
//!
//! Buzz ships the generic OSS contract only: issuer URLs, audiences, and claim
//! names are deployment configuration, never hardcoded.
//!
//! Two deployment-local but deterministic identities are defined here
//! ([NIP-FI.md](../../../../docs/nips/NIP-FI.md), "Policy identity and
//! snapshots"):
//!
//! - [`AssertionPolicyId`] `= H(canonical assertion-policy contract)` — changes
//!   when accepted assertion semantics change, never when key or status
//!   snapshot contents rotate.
//! - [`TransportContractId`] `= H(canonical transport contract)` — identifies
//!   the client-attached field, parsing, attachment, no-fallback, and
//!   context-preservation semantics.

use jsonwebtoken::Algorithm;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

/// Maximum accepted length of an `iss` or `aud` string.
const MAX_URI_LEN: usize = 2_048;
/// Maximum accepted length of a claim name.
const MAX_CLAIM_NAME_LEN: usize = 128;
/// Maximum accepted clock skew, in seconds.
const MAX_SKEW_SECONDS: u64 = 300;
/// Maximum accepted assertion age, in seconds.
const MAX_ASSERTION_AGE_SECONDS: u64 = 86_400;

/// The fixed name of the Nostr-key claim ([NIP-FI.md](../../../../docs/nips/NIP-FI.md),
/// "Assertion validation"). Not configurable: other encodings and aliases deny.
pub const NOSTR_PUBKEY_CLAIM: &str = "nostr_pubkey";

/// Stable identifier for the accepted assertion-policy semantics.
///
/// Deliberately excludes key material, snapshot versions, and mutable state:
/// benign JWKS rotation must not change policy lineage.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AssertionPolicyId([u8; 32]);

impl AssertionPolicyId {
    /// The stable 32-byte policy digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for AssertionPolicyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AssertionPolicyId({})", hex::encode(self.0))
    }
}

/// Stable identifier for the client-attached transport contract semantics.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransportContractId([u8; 32]);

impl TransportContractId {
    /// The core client-attached transport contract identity.
    ///
    /// Covers the exact field name, `Bearer` parsing, request/upgrade
    /// attachment, no-fallback, and context-preservation semantics of
    /// [`super::CLIENT_ATTACHED_HEADER`]. Changing any of those semantics
    /// changes this constant; request data does not.
    pub fn core_client_attached() -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"buzz:nip-fi:transport-contract:v1\0");
        hash_field(&mut hasher, super::CLIENT_ATTACHED_HEADER.as_bytes());
        hash_field(&mut hasher, b"Bearer");
        // No-fallback, request-attached, one-field, context-preserving.
        hash_field(
            &mut hasher,
            b"no-fallback;single-field;request-attached;server-owned-context",
        );
        Self(hasher.finalize().into())
    }

    /// The stable 32-byte transport-contract digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for TransportContractId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TransportContractId({})", hex::encode(self.0))
    }
}

/// The single token class an issuer policy accepts before parsing claims.
/// Policy selects exactly one; failure under one class never triggers another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenClass {
    /// RFC 9068 `at+jwt` access token: protected `typ` is exactly `at+jwt`.
    /// Validated under this document's claim contract, not the full RFC 9068
    /// profile. Requires one non-empty bounded `client_id`; a token whose `sub`
    /// equals its `client_id` is a client-subject token and denies under a
    /// resource-owner policy.
    AccessTokenAtJwt,
    /// A dedicated Buzz assertion: protected `typ` is exactly `nip-fi+jwt`.
    DedicatedNipFi,
    /// Named compatibility access token: absent or generic protected `typ=JWT`.
    /// Only admissible under an explicit policy whose required and forbidden
    /// claims make it mutually exclusive with every ID-token and other class.
    NamedCompatibility {
        /// Claims that MUST be present; their absence denies.
        required_claims: Vec<String>,
        /// Claims that MUST be absent; their presence denies. Used to exclude
        /// OIDC ID tokens (for example `nonce`, `at_hash`, `c_hash`).
        forbidden_claims: Vec<String>,
    },
}

impl TokenClass {
    fn discriminant(&self) -> &'static str {
        match self {
            Self::AccessTokenAtJwt => "at+jwt",
            Self::DedicatedNipFi => "nip-fi+jwt",
            Self::NamedCompatibility { .. } => "named-compat",
        }
    }
}

/// The server-owned freshness class an issuer policy declares. Folded into
/// [`AssertionPolicyId`]. The verifier validates the offline portion; a
/// `CurrentStatus` policy additionally requires a runtime status witness
/// (delivered by a later PR), which the verifier does not itself gather.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshnessClass {
    /// Validates the JWT and authenticated key snapshot only.
    OfflineJwt,
    /// Additionally requires an authenticated current-status witness at runtime.
    CurrentStatus,
}

impl FreshnessClass {
    const fn tag(self) -> &'static str {
        match self {
            Self::OfflineJwt => "offline-jwt",
            Self::CurrentStatus => "current-status",
        }
    }
}

/// One issuer's accepted assertion semantics. Its [`AssertionPolicyId`] is
/// derived from every field below; a semantic change changes the ID.
#[derive(Debug, Clone)]
pub struct IssuerPolicy {
    issuer: String,
    audiences: Vec<String>,
    token_class: TokenClass,
    freshness: FreshnessClass,
    subject_claim: String,
    algorithms: Vec<Algorithm>,
    require_attested_key: bool,
    skew_seconds: u64,
    maximum_assertion_age_seconds: u64,
    maximum_status_age_seconds: Option<u64>,
    id: AssertionPolicyId,
}

/// Why an [`IssuerPolicy`] could not be constructed. Independent of any token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IssuerPolicyError {
    /// `iss` was empty or exceeded the length bound.
    #[error("invalid issuer")]
    InvalidIssuer,
    /// The audience set was empty or contained an invalid value.
    #[error("invalid audience set")]
    InvalidAudiences,
    /// The subject claim name was empty or exceeded the length bound.
    #[error("invalid subject claim")]
    InvalidSubjectClaim,
    /// The algorithm set was empty or contained a symmetric or `none` algorithm.
    #[error("invalid algorithm set")]
    InvalidAlgorithms,
    /// A time or size rule was outside its accepted bound.
    #[error("invalid time bounds")]
    InvalidTimeBounds,
    /// `current-status` freshness requires a positive finite `maximum_status_age`.
    #[error("missing maximum status age")]
    MissingMaximumStatusAge,
    /// A `NamedCompatibility` class declared no required or forbidden claims and
    /// therefore cannot be mutually exclusive with ID tokens.
    #[error("named compatibility policy is not exclusive")]
    NonExclusiveCompatibility,
}

impl IssuerPolicy {
    /// Validate policy fields and derive its stable [`AssertionPolicyId`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        issuer: String,
        audiences: Vec<String>,
        token_class: TokenClass,
        freshness: FreshnessClass,
        subject_claim: String,
        algorithms: Vec<Algorithm>,
        require_attested_key: bool,
        skew_seconds: u64,
        maximum_assertion_age_seconds: u64,
        maximum_status_age_seconds: Option<u64>,
    ) -> Result<Self, IssuerPolicyError> {
        let issuer = issuer.trim().to_owned();
        if issuer.is_empty() || issuer.len() > MAX_URI_LEN {
            return Err(IssuerPolicyError::InvalidIssuer);
        }
        if audiences.is_empty()
            || audiences
                .iter()
                .any(|a| a.trim().is_empty() || a.len() > MAX_URI_LEN)
        {
            return Err(IssuerPolicyError::InvalidAudiences);
        }
        let subject_claim = subject_claim.trim().to_owned();
        if subject_claim.is_empty() || subject_claim.len() > MAX_CLAIM_NAME_LEN {
            return Err(IssuerPolicyError::InvalidSubjectClaim);
        }
        if algorithms.is_empty() || !algorithms.iter().copied().all(is_asymmetric_algorithm) {
            return Err(IssuerPolicyError::InvalidAlgorithms);
        }
        if skew_seconds > MAX_SKEW_SECONDS
            || maximum_assertion_age_seconds == 0
            || maximum_assertion_age_seconds > MAX_ASSERTION_AGE_SECONDS
        {
            return Err(IssuerPolicyError::InvalidTimeBounds);
        }
        match maximum_status_age_seconds {
            Some(0) => return Err(IssuerPolicyError::InvalidTimeBounds),
            None if freshness == FreshnessClass::CurrentStatus => {
                return Err(IssuerPolicyError::MissingMaximumStatusAge);
            }
            _ => {}
        }
        if let TokenClass::NamedCompatibility {
            required_claims,
            forbidden_claims,
        } = &token_class
        {
            if required_claims.is_empty() && forbidden_claims.is_empty() {
                return Err(IssuerPolicyError::NonExclusiveCompatibility);
            }
        }

        let id = derive_assertion_policy_id(
            &issuer,
            &audiences,
            &token_class,
            freshness,
            &subject_claim,
            &algorithms,
            require_attested_key,
            skew_seconds,
            maximum_assertion_age_seconds,
            maximum_status_age_seconds,
        );

        Ok(Self {
            issuer,
            audiences,
            token_class,
            freshness,
            subject_claim,
            algorithms,
            require_attested_key,
            skew_seconds,
            maximum_assertion_age_seconds,
            maximum_status_age_seconds,
            id,
        })
    }

    /// The exact `iss` value this policy is selected by.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The configured audiences; at least one must match the token `aud`.
    pub fn audiences(&self) -> &[String] {
        &self.audiences
    }

    /// The single accepted token class.
    pub fn token_class(&self) -> &TokenClass {
        &self.token_class
    }

    /// The declared freshness class.
    pub const fn freshness(&self) -> FreshnessClass {
        self.freshness
    }

    /// The claim name carrying the opaque subject.
    pub fn subject_claim(&self) -> &str {
        &self.subject_claim
    }

    /// The accepted asymmetric algorithms.
    pub fn algorithms(&self) -> &[Algorithm] {
        &self.algorithms
    }

    /// Whether enrollment requires a `nostr_pubkey` claim equal to the actor.
    pub const fn require_attested_key(&self) -> bool {
        self.require_attested_key
    }

    /// The accepted clock skew, in seconds.
    pub const fn skew_seconds(&self) -> u64 {
        self.skew_seconds
    }

    /// The maximum assertion age, in seconds.
    pub const fn maximum_assertion_age_seconds(&self) -> u64 {
        self.maximum_assertion_age_seconds
    }

    /// The maximum status age, in seconds, when `current-status` is declared.
    pub const fn maximum_status_age_seconds(&self) -> Option<u64> {
        self.maximum_status_age_seconds
    }

    /// The stable policy identity.
    pub const fn id(&self) -> AssertionPolicyId {
        self.id
    }
}

/// A closed set of issuer policies keyed by exact `iss`. Selection preserves
/// every tuple component: equal `sub` under different `iss` are distinct
/// identities.
#[derive(Debug, Clone, Default)]
pub struct IssuerRegistry {
    policies: BTreeMap<String, IssuerPolicy>,
}

impl IssuerRegistry {
    /// An empty registry accepting no issuers.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a policy. Returns the previous policy for the same `iss`, if any.
    pub fn insert(&mut self, policy: IssuerPolicy) -> Option<IssuerPolicy> {
        self.policies.insert(policy.issuer.clone(), policy)
    }

    /// Select the policy for an exact `iss`. No prefix, suffix, or normalization
    /// match is performed.
    pub fn policy_for_issuer(&self, issuer: &str) -> Option<&IssuerPolicy> {
        self.policies.get(issuer)
    }

    /// The number of registered issuers.
    pub fn len(&self) -> usize {
        self.policies.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }
}

/// Whether an algorithm is an accepted asymmetric signature algorithm.
/// `alg=none` and symmetric (HMAC) algorithms are always rejected.
pub(crate) fn is_asymmetric_algorithm(algorithm: Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
            | Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::EdDSA
    )
}

fn algorithm_tag(algorithm: Algorithm) -> &'static str {
    match algorithm {
        Algorithm::HS256 => "HS256",
        Algorithm::HS384 => "HS384",
        Algorithm::HS512 => "HS512",
        Algorithm::RS256 => "RS256",
        Algorithm::RS384 => "RS384",
        Algorithm::RS512 => "RS512",
        Algorithm::ES256 => "ES256",
        Algorithm::ES384 => "ES384",
        Algorithm::PS256 => "PS256",
        Algorithm::PS384 => "PS384",
        Algorithm::PS512 => "PS512",
        Algorithm::EdDSA => "EdDSA",
    }
}

#[allow(clippy::too_many_arguments)]
fn derive_assertion_policy_id(
    issuer: &str,
    audiences: &[String],
    token_class: &TokenClass,
    freshness: FreshnessClass,
    subject_claim: &str,
    algorithms: &[Algorithm],
    require_attested_key: bool,
    skew_seconds: u64,
    maximum_assertion_age_seconds: u64,
    maximum_status_age_seconds: Option<u64>,
) -> AssertionPolicyId {
    let mut hasher = Sha256::new();
    hasher.update(b"buzz:nip-fi:assertion-policy:v1\0");
    hash_field(&mut hasher, issuer.as_bytes());
    hash_seq(&mut hasher, audiences.iter().map(String::as_bytes));
    hash_field(&mut hasher, token_class.discriminant().as_bytes());
    if let TokenClass::NamedCompatibility {
        required_claims,
        forbidden_claims,
    } = token_class
    {
        hash_seq(&mut hasher, required_claims.iter().map(String::as_bytes));
        hash_seq(&mut hasher, forbidden_claims.iter().map(String::as_bytes));
    }
    hash_field(&mut hasher, freshness.tag().as_bytes());
    hash_field(&mut hasher, subject_claim.as_bytes());
    hash_field(&mut hasher, NOSTR_PUBKEY_CLAIM.as_bytes());
    hash_seq(
        &mut hasher,
        algorithms.iter().map(|a| algorithm_tag(*a).as_bytes()),
    );
    hasher.update([u8::from(require_attested_key)]);
    hasher.update(skew_seconds.to_be_bytes());
    hasher.update(maximum_assertion_age_seconds.to_be_bytes());
    hasher.update(maximum_status_age_seconds.unwrap_or(0).to_be_bytes());
    AssertionPolicyId(hasher.finalize().into())
}

/// Length-prefix one field so distinct field boundaries cannot collide.
fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

/// Length-prefix a sequence: element count, then each length-prefixed element.
fn hash_seq<'a>(hasher: &mut Sha256, items: impl ExactSizeIterator<Item = &'a [u8]>) {
    hasher.update((items.len() as u64).to_be_bytes());
    for item in items {
        hash_field(hasher, item);
    }
}
