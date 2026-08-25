//! Behavior tests for the NIP-FI canonical assertion verifier and contracts
//! (PR 1). Exercises the exact-wire-text denial contract, deterministic
//! contract IDs, token-class enforcement including ID-token denial, and
//! multi-issuer `(iss, sub)` selection, against real ES256-signed assertions.

use buzz_auth::{
    AssertionKeySet, DenialClass, FederatedAssertionVerifier, FreshnessClass, IssuerPolicy,
    IssuerRegistry, TokenClass, TransportContractId, VerifierError, CLIENT_ATTACHED_HEADER,
    NOSTR_PUBKEY_CLAIM,
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
    AssertionKeySet::new(1, test_jwks(TEST_KID), None).expect("nonzero generation")
}

fn access_token_policy() -> IssuerPolicy {
    IssuerPolicy::new(
        ISSUER.to_owned(),
        vec![AUDIENCE.to_owned()],
        TokenClass::AccessTokenAtJwt,
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

// ---- Happy path ----------------------------------------------------------

#[test]
fn valid_access_token_verifies() {
    let verifier = verifier_with(access_token_policy());
    let token = mint(
        Some("at+jwt"),
        TEST_KID,
        json!({ "sub": "user-123", "client_id": "app-1" }),
    );
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
        json!({ "sub": "user-123", "client_id": "app-1", "nonce": "n" }),
    );
    let err = verifier.verify(&token, &key_set()).unwrap_err();
    assert_eq!(err, VerifierError::TokenTypeRejected);
    assert_eq!(err.denial_class(), DenialClass::EvidenceRejected);
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
    let token = mint(Some("at+jwt"), TEST_KID, json!({ "sub": "user-123" }));
    assert_eq!(
        verifier.verify(&token, &key_set()).unwrap_err(),
        VerifierError::ClaimContractRejected
    );
}

#[test]
fn access_token_with_subject_equal_client_id_denies() {
    let verifier = verifier_with(access_token_policy());
    let token = mint(
        Some("at+jwt"),
        TEST_KID,
        json!({ "sub": "app-1", "client_id": "app-1" }),
    );
    assert_eq!(
        verifier.verify(&token, &key_set()).unwrap_err(),
        VerifierError::ClaimContractRejected
    );
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
        json!({ "sub": "u", "client_id": "a", NOSTR_PUBKEY_CLAIM: real }),
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
        json!({ "sub": "u", "client_id": "a", NOSTR_PUBKEY_CLAIM: upper }),
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
        json!({ "sub": "u", "client_id": "a", "iat": now() - 1200, "exp": now() - 600 }),
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
        json!({ "sub": "u", "client_id": "a", "iat": now() - 4000, "exp": now() + 600 }),
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
        .verify(&sign(issuer_a), &key_set())
        .expect("a verifies");
    let b = verifier
        .verify(&sign(issuer_b), &key_set())
        .expect("b verifies");
    assert_eq!(a.identity().subject(), b.identity().subject());
    assert_ne!(a.identity().issuer(), b.identity().issuer());
    assert_ne!(a.assertion_policy_id(), b.assertion_policy_id());
}

// ---- Deterministic contract IDs ------------------------------------------

#[test]
fn assertion_policy_id_is_deterministic_and_semantic() {
    let p1 = access_token_policy();
    let p2 = access_token_policy();
    assert_eq!(p1.id(), p2.id(), "same contract => same id");

    let changed = IssuerPolicy::new(
        ISSUER.to_owned(),
        vec![AUDIENCE.to_owned()],
        TokenClass::AccessTokenAtJwt,
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
