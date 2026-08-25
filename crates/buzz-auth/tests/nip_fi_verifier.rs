//! Behavior tests for the NIP-FI canonical assertion verifier and contracts
//! (PR 1). Exercises the exact-wire-text denial contract, deterministic
//! contract IDs, token-class enforcement including ID-token denial, and
//! multi-issuer `(iss, sub)` selection, against real ES256-signed assertions.

use buzz_auth::{
    AssertionKeySet, ClientSubjectPosture, DenialClass, FederatedAssertionVerifier, FreshnessClass,
    IssuerPolicy, IssuerPolicyError, IssuerRegistry, SubjectClassContract, TokenClass,
    TransportContractId, VerifierError, CLIENT_ATTACHED_HEADER, NOSTR_PUBKEY_CLAIM,
    OAUTH_CLIENT_ID_CLAIM,
};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{json, Value};

// A fixed P-256 test key (PKCS#8 PEM) and its public JWK coordinates.
const TEST_EC_PKCS8_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcnxDM4EiirH9dHUE\n\
WZc759TX4s5PAn8kO5ovXSnGxCWhRANCAARFb6ZnsfkqOOXyEhj3KBQphGKF4vTa\n\
zhebbavbZ1ZoklqkF1cGg+jTO7rONAVEzXvXUWtV6CdDV+rybiVmFP2w\n\
-----END PRIVATE KEY-----\n";
const TEST_JWK_X: &str = "RW-mZ7H5Kjjl8hIY9ygUKYRiheL02s4Xm22r22dWaJI";
const TEST_JWK_Y: &str = "WqQXVwaD6NM7us40BUTNe9dRa1XoJ0NX6vJuJWYU_bA";
const TEST_KID: &str = "test-key-1";
const ISSUER: &str = "https://issuer.example";
const AUDIENCE: &str = "https://relay.example";

fn test_jwks(kid: &str) -> JwkSet {
    serde_json::from_value(json!({
        "keys": [{
            "kty": "EC",
            "crv": "P-256",
            "use": "sig",
            "alg": "ES256",
            "kid": kid,
            "x": TEST_JWK_X,
            "y": TEST_JWK_Y,
        }]
    }))
    .expect("valid JWKS")
}

fn key_set() -> AssertionKeySet {
    key_set_for(ISSUER)
}

fn key_set_for(issuer: &str) -> AssertionKeySet {
    AssertionKeySet::new(issuer.to_owned(), 1, test_jwks(TEST_KID), None)
        .expect("nonzero generation, non-empty issuer")
}

/// A resource-owner/client-subject contract that rejects client-subject tokens.
/// Resource-owner and client-subject subjects are distinguished by a `sub_type`
/// marker claim with disjoint value sets.
fn subject_class_reject() -> SubjectClassContract {
    SubjectClassContract::new(
        "sub_type".to_owned(),
        vec!["user".to_owned()],
        vec!["client".to_owned()],
        ClientSubjectPosture::Reject,
    )
    .expect("valid subject-class contract")
}

fn access_token_policy() -> IssuerPolicy {
    access_token_policy_with(subject_class_reject())
}

fn access_token_policy_with(subject_class: SubjectClassContract) -> IssuerPolicy {
    IssuerPolicy::new(
        ISSUER.to_owned(),
        vec![AUDIENCE.to_owned()],
        TokenClass::AccessTokenAtJwt { subject_class },
        FreshnessClass::OfflineJwt,
        "sub".to_owned(),
        vec![Algorithm::ES256],
        false,
        60,
        3600,
        None,
    )
    .expect("valid policy")
}

fn dedicated_policy(issuer: &str) -> IssuerPolicy {
    IssuerPolicy::new(
        issuer.to_owned(),
        vec![AUDIENCE.to_owned()],
        TokenClass::DedicatedNipFi,
        FreshnessClass::OfflineJwt,
        "sub".to_owned(),
        vec![Algorithm::ES256],
        false,
        60,
        3600,
        None,
    )
    .expect("valid policy")
}

fn verifier_with(policy: IssuerPolicy) -> FederatedAssertionVerifier {
    let mut registry = IssuerRegistry::new();
    registry.insert(policy);
    FederatedAssertionVerifier::new(registry)
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn signing_key() -> EncodingKey {
    EncodingKey::from_ec_pem(TEST_EC_PKCS8_PEM.as_bytes()).expect("valid EC PEM")
}

/// Mint a signed ES256 assertion with the given `typ`, `kid`, and claims.
/// Fills in default `iss`/`aud`/`iat`/`exp` if absent.
fn mint(typ: Option<&str>, kid: &str, mut claims: Value) -> String {
    {
        let obj = claims.as_object_mut().expect("claims object");
        obj.entry("iss").or_insert(json!(ISSUER));
        obj.entry("aud").or_insert(json!(AUDIENCE));
        obj.entry("iat").or_insert(json!(now()));
        obj.entry("exp").or_insert(json!(now() + 600));
    }
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(kid.to_owned());
    header.typ = typ.map(str::to_owned);
    jsonwebtoken::encode(&header, &claims, &signing_key()).expect("sign")
}

/// A resource-owner `at+jwt` claim set: valid subject-class marker plus client_id.
fn resource_owner_claims() -> Value {
    json!({ "sub": "user-123", "client_id": "app-1", "sub_type": "user" })
}

/// Base64url-encode a JSON string into a JWS segment.
fn b64_segment(json_text: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json_text.as_bytes())
}

// ---- Happy path ----------------------------------------------------------

#[test]
fn valid_access_token_verifies() {
    let verifier = verifier_with(access_token_policy());
    let token = mint(Some("at+jwt"), TEST_KID, resource_owner_claims());
    let assertion = verifier.verify(&token, &key_set()).expect("verifies");
    assert_eq!(assertion.identity().issuer(), ISSUER);
    assert_eq!(assertion.identity().subject(), "user-123");
    assert!(assertion.asserted_key().is_none());
    assert!(!assertion.authority_deadlines().is_empty());
    assert_eq!(assertion.assertion_policy_id(), access_token_policy().id());
}

// ---- Token class / typ enforcement, ID-token denial ----------------------

#[test]
fn id_token_denies_even_when_iss_aud_sub_match() {
    let verifier = verifier_with(access_token_policy());
    let token = mint(
        Some("JWT"),
        TEST_KID,
        json!({ "sub": "user-123", "client_id": "app-1", "sub_type": "user", "nonce": "n" }),
    );
    let err = verifier.verify(&token, &key_set()).unwrap_err();
    assert_eq!(err, VerifierError::TokenTypeRejected);
    assert_eq!(err.denial_class(), DenialClass::EvidenceRejected);
}

// ---- Named-compatibility exclusivity vs OIDC ID tokens -------------------

fn named_compat_policy() -> IssuerPolicy {
    IssuerPolicy::new(
        ISSUER.to_owned(),
        vec![AUDIENCE.to_owned()],
        TokenClass::NamedCompatibility {
            // Requiring the access-token-only `client_id` claim is what proves
            // exclusivity with every OIDC ID token.
            required_claims: vec![OAUTH_CLIENT_ID_CLAIM.to_owned()],
            forbidden_claims: vec!["nonce".to_owned()],
        },
        FreshnessClass::OfflineJwt,
        "sub".to_owned(),
        vec![Algorithm::ES256],
        false,
        60,
        3600,
        None,
    )
    .expect("valid named-compat policy")
}

#[test]
fn named_compat_policy_requires_client_id_claim() {
    // A named-compat policy that does not require `client_id` cannot be proven
    // mutually exclusive with ID tokens, so construction is rejected.
    let err = IssuerPolicy::new(
        ISSUER.to_owned(),
        vec![AUDIENCE.to_owned()],
        TokenClass::NamedCompatibility {
            required_claims: vec!["scope".to_owned()],
            forbidden_claims: vec!["nonce".to_owned()],
        },
        FreshnessClass::OfflineJwt,
        "sub".to_owned(),
        vec![Algorithm::ES256],
        false,
        60,
        3600,
        None,
    )
    .unwrap_err();
    assert_eq!(err, IssuerPolicyError::NonExclusiveCompatibility);
}

#[test]
fn named_compat_accepts_access_token_with_generic_typ() {
    let verifier = verifier_with(named_compat_policy());
    // Generic `typ=JWT` access token carrying `client_id`.
    let token = mint(
        Some("JWT"),
        TEST_KID,
        json!({ "sub": "user-123", "client_id": "app-1" }),
    );
    assert!(verifier.verify(&token, &key_set()).is_ok());
}

#[test]
fn named_compat_denies_generic_oidc_id_token() {
    let verifier = verifier_with(named_compat_policy());
    // A realistic OIDC ID token: generic `typ`, matching iss/aud/sub, no
    // `client_id`. It fails the required-claim rule.
    let token = mint(
        None,
        TEST_KID,
        json!({ "sub": "user-123", "nonce": "abc", "at_hash": "xyz" }),
    );
    assert_eq!(
        verifier.verify(&token, &key_set()).unwrap_err(),
        VerifierError::ClaimContractRejected
    );
}

#[test]
fn dedicated_class_rejects_at_jwt_typ_and_accepts_nip_fi() {
    let verifier = verifier_with(dedicated_policy(ISSUER));
    let wrong = mint(Some("at+jwt"), TEST_KID, json!({ "sub": "u" }));
    assert_eq!(
        verifier.verify(&wrong, &key_set()).unwrap_err(),
        VerifierError::TokenTypeRejected
    );
    let ok = mint(Some("nip-fi+jwt"), TEST_KID, json!({ "sub": "u" }));
    assert!(verifier.verify(&ok, &key_set()).is_ok());
}

#[test]
fn access_token_without_client_id_denies() {
    let verifier = verifier_with(access_token_policy());
    let token = mint(
        Some("at+jwt"),
        TEST_KID,
        json!({ "sub": "user-123", "sub_type": "user" }),
    );
    assert_eq!(
        verifier.verify(&token, &key_set()).unwrap_err(),
        VerifierError::ClaimContractRejected
    );
}

// ---- Resource-owner / client-subject classification ----------------------

#[test]
fn resource_owner_marker_verifies() {
    let verifier = verifier_with(access_token_policy());
    let token = mint(
        Some("at+jwt"),
        TEST_KID,
        json!({ "sub": "user-123", "client_id": "app-1", "sub_type": "user" }),
    );
    assert!(verifier.verify(&token, &key_set()).is_ok());
}

#[test]
fn client_subject_marker_denies_under_reject_posture() {
    let verifier = verifier_with(access_token_policy());
    let token = mint(
        Some("at+jwt"),
        TEST_KID,
        json!({ "sub": "svc-1", "client_id": "app-1", "sub_type": "client" }),
    );
    assert_eq!(
        verifier.verify(&token, &key_set()).unwrap_err(),
        VerifierError::ClaimContractRejected
    );
}

#[test]
fn client_subject_marker_verifies_under_accept_non_colliding_posture() {
    let contract = SubjectClassContract::new(
        "sub_type".to_owned(),
        vec!["user".to_owned()],
        vec!["client".to_owned()],
        ClientSubjectPosture::AcceptNonColliding,
    )
    .unwrap();
    let verifier = verifier_with(access_token_policy_with(contract));
    let token = mint(
        Some("at+jwt"),
        TEST_KID,
        json!({ "sub": "svc-1", "client_id": "app-1", "sub_type": "client" }),
    );
    assert!(verifier.verify(&token, &key_set()).is_ok());
}

#[test]
fn unclassifiable_subject_marker_denies() {
    // A marker value in neither set cannot be classified as resource-owner or
    // client-subject, so the token is ambiguous and denies.
    let verifier = verifier_with(access_token_policy());
    let token = mint(
        Some("at+jwt"),
        TEST_KID,
        json!({ "sub": "user-123", "client_id": "app-1", "sub_type": "mystery" }),
    );
    assert_eq!(
        verifier.verify(&token, &key_set()).unwrap_err(),
        VerifierError::ClaimContractRejected
    );
}

#[test]
fn subject_class_contract_rejects_overlapping_value_sets() {
    let err = SubjectClassContract::new(
        "sub_type".to_owned(),
        vec!["user".to_owned(), "shared".to_owned()],
        vec!["shared".to_owned()],
        ClientSubjectPosture::Reject,
    )
    .unwrap_err();
    assert_eq!(err, IssuerPolicyError::NonExclusiveSubjectClass);
}

// ---- Algorithm / key rejection -------------------------------------------

#[test]
fn hs256_symmetric_algorithm_denies() {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = b64.encode(json!({"alg":"HS256","kid":TEST_KID,"typ":"at+jwt"}).to_string());
    let payload = b64.encode(
        json!({"iss":ISSUER,"aud":AUDIENCE,"sub":"u","client_id":"a","iat":now(),"exp":now()+600})
            .to_string(),
    );
    let token = format!("{header}.{payload}.AAAA");
    let verifier = verifier_with(access_token_policy());
    assert_eq!(
        verifier.verify(&token, &key_set()).unwrap_err(),
        VerifierError::UnsupportedAlgorithm
    );
}

#[test]
fn alg_none_denies() {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = b64.encode(json!({"alg":"none","kid":TEST_KID,"typ":"at+jwt"}).to_string());
    let payload = b64.encode(json!({"iss":ISSUER,"aud":AUDIENCE,"sub":"u"}).to_string());
    let token = format!("{header}.{payload}.");
    let verifier = verifier_with(access_token_policy());
    assert_eq!(
        verifier.verify(&token, &key_set()).unwrap_err(),
        VerifierError::UnsupportedAlgorithm
    );
}

#[test]
fn unknown_kid_denies() {
    let verifier = verifier_with(access_token_policy());
    let token = mint(
        Some("at+jwt"),
        "other-kid",
        json!({ "sub": "u", "client_id": "a" }),
    );
    assert_eq!(
        verifier.verify(&token, &key_set()).unwrap_err(),
        VerifierError::AmbiguousKeyId
    );
}

#[test]
fn tampered_signature_denies() {
    let verifier = verifier_with(access_token_policy());
    let mut token = mint(
        Some("at+jwt"),
        TEST_KID,
        json!({ "sub": "u", "client_id": "a" }),
    );
    // Flip the last signature character.
    let last = token.pop().unwrap();
    token.push(if last == 'A' { 'B' } else { 'A' });
    assert_eq!(
        verifier.verify(&token, &key_set()).unwrap_err(),
        VerifierError::InvalidSignatureOrClaims
    );
}

#[test]
fn wrong_audience_denies() {
    let verifier = verifier_with(access_token_policy());
    let token = mint(
        Some("at+jwt"),
        TEST_KID,
        json!({ "sub": "u", "client_id": "a", "aud": "https://other.example" }),
    );
    assert_eq!(
        verifier.verify(&token, &key_set()).unwrap_err(),
        VerifierError::InvalidSignatureOrClaims
    );
}

// ---- nostr_pubkey handling -----------------------------------------------

#[test]
fn lowercase_hex_nostr_pubkey_is_accepted() {
    let verifier = verifier_with(access_token_policy());
    let real = nostr::Keys::generate().public_key().to_hex();
    let token = mint(
        Some("at+jwt"),
        TEST_KID,
        json!({ "sub": "u", "client_id": "a", "sub_type": "user", NOSTR_PUBKEY_CLAIM: real }),
    );
    let assertion = verifier.verify(&token, &key_set()).expect("verifies");
    assert!(assertion.asserted_key().is_some());
}

#[test]
fn uppercase_nostr_pubkey_denies() {
    let verifier = verifier_with(access_token_policy());
    let upper = nostr::Keys::generate().public_key().to_hex().to_uppercase();
    let token = mint(
        Some("at+jwt"),
        TEST_KID,
        json!({ "sub": "u", "client_id": "a", "sub_type": "user", NOSTR_PUBKEY_CLAIM: upper }),
    );
    assert_eq!(
        verifier.verify(&token, &key_set()).unwrap_err(),
        VerifierError::ClaimRejected
    );
}

#[test]
fn missing_nostr_pubkey_denies_under_attested_key_policy() {
    let policy = IssuerPolicy::new(
        ISSUER.to_owned(),
        vec![AUDIENCE.to_owned()],
        TokenClass::DedicatedNipFi,
        FreshnessClass::OfflineJwt,
        "sub".to_owned(),
        vec![Algorithm::ES256],
        true, // require attested key
        60,
        3600,
        None,
    )
    .unwrap();
    let verifier = verifier_with(policy);
    let token = mint(Some("nip-fi+jwt"), TEST_KID, json!({ "sub": "u" }));
    assert_eq!(
        verifier.verify(&token, &key_set()).unwrap_err(),
        VerifierError::ClaimRejected
    );
}

// ---- Time bounds ----------------------------------------------------------

#[test]
fn expired_assertion_denies() {
    let verifier = verifier_with(access_token_policy());
    let token = mint(
        Some("at+jwt"),
        TEST_KID,
        json!({ "sub": "u", "client_id": "a", "sub_type": "user", "iat": now() - 1200, "exp": now() - 600 }),
    );
    assert_eq!(
        verifier.verify(&token, &key_set()).unwrap_err(),
        VerifierError::Expired
    );
}

#[test]
fn assertion_beyond_maximum_age_denies() {
    let verifier = verifier_with(access_token_policy());
    let token = mint(
        Some("at+jwt"),
        TEST_KID,
        json!({ "sub": "u", "client_id": "a", "sub_type": "user", "iat": now() - 4000, "exp": now() + 600 }),
    );
    assert_eq!(
        verifier.verify(&token, &key_set()).unwrap_err(),
        VerifierError::Expired
    );
}

// ---- Multi-issuer selection ----------------------------------------------

#[test]
fn unknown_issuer_denies() {
    let verifier = verifier_with(access_token_policy());
    let token = mint(
        Some("at+jwt"),
        TEST_KID,
        json!({ "sub": "u", "client_id": "a", "iss": "https://evil.example" }),
    );
    assert_eq!(
        verifier.verify(&token, &key_set()).unwrap_err(),
        VerifierError::UnknownIssuer
    );
}

#[test]
fn same_subject_distinct_issuers_are_distinct_identities() {
    let issuer_a = "https://a.example";
    let issuer_b = "https://b.example";
    let policy_a = dedicated_policy(issuer_a);
    let policy_b = dedicated_policy(issuer_b);
    assert_ne!(policy_a.id(), policy_b.id());

    let mut registry = IssuerRegistry::new();
    registry.insert(policy_a);
    registry.insert(policy_b);
    let verifier = FederatedAssertionVerifier::new(registry);

    let sign = |iss: &str| {
        let claims = json!({ "sub": "shared-sub", "iss": iss });
        mint(Some("nip-fi+jwt"), TEST_KID, claims)
    };
    let a = verifier
        .verify(&sign(issuer_a), &key_set_for(issuer_a))
        .expect("a verifies");
    let b = verifier
        .verify(&sign(issuer_b), &key_set_for(issuer_b))
        .expect("b verifies");
    assert_eq!(a.identity().subject(), b.identity().subject());
    assert_ne!(a.identity().issuer(), b.identity().issuer());
    assert_ne!(a.assertion_policy_id(), b.assertion_policy_id());
}

// ---- Cross-issuer key binding (CRITICAL #1) ------------------------------

#[test]
fn key_snapshot_bound_to_its_issuer_blocks_cross_issuer_use() {
    // Two issuers whose policies share every field except `iss`, so only the
    // key binding — not policy shape — can stop the cross-issuer forgery. The
    // same test key backs both snapshots, so the signature would otherwise
    // verify.
    let issuer_a = "https://a.example";
    let issuer_b = "https://b.example";
    let mut registry = IssuerRegistry::new();
    registry.insert(dedicated_policy(issuer_a));
    registry.insert(dedicated_policy(issuer_b));
    let verifier = FederatedAssertionVerifier::new(registry);

    // Token claims issuer A; caller mistakenly supplies issuer B's snapshot.
    let token = mint(
        Some("nip-fi+jwt"),
        TEST_KID,
        json!({ "sub": "u", "iss": issuer_a }),
    );
    assert_eq!(
        verifier.verify(&token, &key_set_for(issuer_b)).unwrap_err(),
        VerifierError::IssuerKeyMismatch
    );
    // The correctly bound snapshot verifies.
    assert!(verifier.verify(&token, &key_set_for(issuer_a)).is_ok());
}

// ---- Duplicate-member rejection (IMPORTANT #2) ---------------------------
//
// Duplicate members are rejected while parsing the protected header and the
// claims segment — both before signature verification — so these tokens carry
// a dummy signature; the parse denies first.

#[test]
fn duplicate_claim_member_denies() {
    let verifier = verifier_with(access_token_policy());
    // Duplicate `sub`: last-wins parsing would silently pick "attacker".
    let claims = format!(
        r#"{{"iss":"{ISSUER}","aud":"{AUDIENCE}","iat":{iat},"exp":{exp},"client_id":"a","sub_type":"user","sub":"victim","sub":"attacker"}}"#,
        iat = now(),
        exp = now() + 600,
    );
    let header = r#"{"alg":"ES256","kid":"test-key-1","typ":"at+jwt"}"#;
    let token = format!("{}.{}.AAAA", b64_segment(header), b64_segment(&claims));
    assert_eq!(
        verifier.verify(&token, &key_set()).unwrap_err(),
        VerifierError::DuplicateMember
    );
}

#[test]
fn duplicate_header_member_denies() {
    let verifier = verifier_with(access_token_policy());
    // Duplicate `alg` in the protected header; last-wins would read "none".
    let header = r#"{"alg":"ES256","alg":"none","kid":"test-key-1","typ":"at+jwt"}"#;
    let claims = format!(
        r#"{{"iss":"{ISSUER}","aud":"{AUDIENCE}","iat":{iat},"exp":{exp},"client_id":"a","sub":"u","sub_type":"user"}}"#,
        iat = now(),
        exp = now() + 600,
    );
    let token = format!("{}.{}.AAAA", b64_segment(header), b64_segment(&claims));
    assert_eq!(
        verifier.verify(&token, &key_set()).unwrap_err(),
        VerifierError::DuplicateMember
    );
}

// ---- CurrentStatus deferral (IMPORTANT #7) -------------------------------

#[test]
fn current_status_policy_denies_without_witness() {
    let policy = IssuerPolicy::new(
        ISSUER.to_owned(),
        vec![AUDIENCE.to_owned()],
        TokenClass::DedicatedNipFi,
        FreshnessClass::CurrentStatus,
        "sub".to_owned(),
        vec![Algorithm::ES256],
        false,
        60,
        3600,
        Some(120), // maximum_status_age required for current-status
    )
    .expect("valid current-status policy");
    let verifier = verifier_with(policy);
    let token = mint(Some("nip-fi+jwt"), TEST_KID, json!({ "sub": "u" }));
    assert_eq!(
        verifier.verify(&token, &key_set()).unwrap_err(),
        VerifierError::StatusWitnessUnavailable
    );
}

#[test]
fn subject_bytes_are_preserved_exactly_not_trimmed() {
    // A subject with surrounding whitespace must survive verbatim: trimming
    // would collapse distinct byte strings into one identity.
    let verifier = verifier_with(access_token_policy());
    let token = mint(
        Some("at+jwt"),
        TEST_KID,
        json!({ "sub": " user-123 ", "client_id": "app-1", "sub_type": "user" }),
    );
    let assertion = verifier.verify(&token, &key_set()).expect("verifies");
    assert_eq!(assertion.identity().subject(), " user-123 ");
}

// ---- Deterministic contract IDs ------------------------------------------

#[test]
fn assertion_policy_id_is_deterministic_and_semantic() {
    let p1 = access_token_policy();
    let p2 = access_token_policy();
    assert_eq!(p1.id(), p2.id(), "same contract => same id");

    let changed = access_token_policy_with(subject_class_reject());
    let changed = IssuerPolicy::new(
        ISSUER.to_owned(),
        vec![AUDIENCE.to_owned()],
        changed.token_class().clone(),
        FreshnessClass::OfflineJwt,
        "sub".to_owned(),
        vec![Algorithm::ES256],
        false,
        120, // different skew => different semantics
        3600,
        None,
    )
    .unwrap();
    assert_ne!(p1.id(), changed.id());
}

#[test]
fn assertion_policy_id_moves_with_subject_class_contract() {
    // The subject-class contract is a normative input to the policy ID.
    let base = access_token_policy_with(subject_class_reject());
    let different_values = access_token_policy_with(
        SubjectClassContract::new(
            "sub_type".to_owned(),
            vec!["human".to_owned()], // different resource-owner value set
            vec!["client".to_owned()],
            ClientSubjectPosture::Reject,
        )
        .unwrap(),
    );
    let different_posture = access_token_policy_with(
        SubjectClassContract::new(
            "sub_type".to_owned(),
            vec!["user".to_owned()],
            vec!["client".to_owned()],
            ClientSubjectPosture::AcceptNonColliding, // different posture
        )
        .unwrap(),
    );
    assert_ne!(base.id(), different_values.id());
    assert_ne!(base.id(), different_posture.id());
}

#[test]
fn transport_contract_id_is_stable() {
    assert_eq!(
        TransportContractId::core_client_attached(),
        TransportContractId::core_client_attached()
    );
    assert_eq!(CLIENT_ATTACHED_HEADER, "Nostr-Federated-Identity");
}

// ---- Exact-wire-text denial contract (all four classes) ------------------

#[test]
fn denial_classes_carry_exact_wire_text() {
    let m = DenialClass::MissingEvidence;
    assert_eq!(m.nostr_text(), "auth-required: authentication required");
    assert_eq!(m.http_status(), 401);
    assert_eq!(m.http_body(), "authentication required\n");
    assert_eq!(m.www_authenticate(), Some("Nostr"));
    assert_eq!(m.content_type(), "text/plain; charset=utf-8");

    let e = DenialClass::EvidenceRejected;
    assert_eq!(e.nostr_text(), "restricted: evidence rejected");
    assert_eq!(e.http_status(), 403);
    assert_eq!(e.http_body(), "evidence rejected\n");
    assert_eq!(e.www_authenticate(), None);

    let d = DenialClass::AuthorizationDenied;
    assert_eq!(d.nostr_text(), "restricted: authorization denied");
    assert_eq!(d.http_status(), 403);
    assert_eq!(d.http_body(), "authorization denied\n");

    let u = DenialClass::AuthorizationUnavailable;
    assert_eq!(u.nostr_text(), "restricted: authorization unavailable");
    assert_eq!(u.http_status(), 503);
    assert_eq!(u.http_body(), "authorization unavailable\n");
}
