//! Isolated workflow-delivery verifier (node E of the workflow replacement
//! tree).
//!
//! Centralizes exact definition / message / owner / channel / step / cause
//! verification for durable workflow deliveries. This module is **pure**: it
//! performs no network or database I/O and has no production caller yet — the
//! capability-gated ACP runtime (node F) wires it up. Callers fetch the
//! signed events (definition, visible message, cause) themselves and hand
//! them to the verifier.
//!
//! Every check is fail-closed. A typed [`VerifyError`] distinguishes
//! permanent [`Mismatch`](VerifyError::Mismatch) outcomes (the delivery can
//! never verify — binding fields disagree, authority is malformed, or content
//! was forged) from transient [`Unavailable`](VerifyError::Unavailable)
//! outcomes (a required input was not supplied or could not be fetched).
//! Neither variant may become dispatch; `Unavailable` may be retried.

use std::collections::HashMap;

use buzz_core::kind::{KIND_STREAM_MESSAGE, KIND_WORKFLOW_DEF};
use buzz_core::tenant::CommunityId;
use buzz_core::workflow_delivery::{
    message_v1_targets, WorkflowDeliveryCause, WorkflowDeliveryId, WorkflowDeliveryWake,
};
use uuid::Uuid;

/// Immutable snapshot of a claimed delivery, as the runtime would present it
/// for verification. Pure data — the claim/lease lifecycle lives elsewhere.
///
/// This is the DB-shaped record view (identifiers as stored hex strings);
/// [`buzz_core::workflow_delivery::WorkflowDeliveryBinding`] remains the
/// canonical comparison authority for producers and durable state. The
/// verifier converts and fails closed on any field that does not parse.
#[derive(Clone, Debug)]
pub struct DeliverySnapshot {
    pub id: Uuid,
    /// Server-resolved tenant that owns the delivery. Originates from the
    /// scoped DB row (never client input), matching the
    /// [`CommunityId::from_uuid`] contract.
    pub community_id: CommunityId,
    pub workflow_id: Uuid,
    pub run_id: Uuid,
    pub step_id: String,
    pub definition_event_id: String,
    pub message_event_id: String,
    pub channel_id: Uuid,
    pub target_pubkey: String,
    /// Canonical identity of the authority that caused this run.
    pub cause: WorkflowDeliveryCause,
    pub execution_trace: serde_json::Value,
    pub trigger_context: Option<serde_json::Value>,
}

/// Why verification permanently failed. Retrying with the same inputs can
/// never succeed; the delivery must be finished as failed, never dispatched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MismatchKind {
    /// The delivery targets a different agent pubkey.
    Target,
    /// Definition event kind, `d` tag workflow UUID, or `h` channel binding
    /// disagrees with the delivery snapshot.
    Definition,
    /// Visible message kind, channel, relay authorship, or required tags
    /// disagree with the delivery snapshot.
    Message,
    /// The signed definition failed to parse, the bound step is absent, or
    /// the step is not a send_message action.
    Step,
    /// The step's channel field names a different channel.
    Channel,
    /// The trigger context is bound to a different definition revision.
    Revision,
    /// The rendered template disagrees with the visible message content.
    Content,
    /// The independent cause authority disagrees with the recorded cause or
    /// the delivery's binding (tenant, workflow, linked run), is of the wrong
    /// class, is authored in a different channel, or fails signature
    /// verification.
    Cause,
}

/// Why verification could not be performed. The required authority was not
/// supplied (or could not be fetched by the caller). May be retried; must
/// never become dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnavailableKind {
    /// The signed definition event was not supplied.
    Definition,
    /// The visible message event was not supplied.
    Message,
    /// The delivery has no parseable trigger context.
    TriggerContext,
    /// The execution trace is absent or malformed.
    ExecutionTrace,
    /// The delivery's recorded cause requires independent authority (signed
    /// event, durable schedule claim row, or durable webhook invocation
    /// record) and none was supplied.
    Cause,
    /// The relay identity needed to authenticate relay-authored events is
    /// unknown.
    RelayIdentity,
}

/// Typed verification outcome. `Mismatch` is permanent, `Unavailable` is
/// transient; neither is dispatchable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    Mismatch(MismatchKind),
    Unavailable(UnavailableKind),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::Mismatch(kind) => write!(f, "permanent mismatch: {kind:?}"),
            VerifyError::Unavailable(kind) => write!(f, "authority unavailable: {kind:?}"),
        }
    }
}

/// Independent, caller-fetched authority for the recorded cause.
///
/// The claimed delivery row is never its own proof: every cause class must be
/// re-established from durable or signed authority the caller fetched —
/// the exact signed cause event, the durable schedule claim row, or the
/// durable webhook invocation record (owned by a later node; modeled here as
/// the bound identity that record must supply).
///
/// Durable authority must carry the source row's full binding identity, not
/// just the scalar the delivery re-presents: a timestamp or invocation id
/// copied from the delivery row proves nothing, and two workflows can fire
/// at the same schedule slot.
#[derive(Clone, Copy, Debug)]
pub enum CauseAuthority<'a> {
    /// The exact signed cause event.
    Event(&'a nostr::Event),
    /// The durable schedule claim, read from the independent
    /// `scheduled_workflow_fires` row — keyed by
    /// `(community_id, workflow_id, scheduled_for)` and linking the run it
    /// created — never from the claimed delivery.
    Schedule {
        /// Tenant that owns the claim row.
        community_id: CommunityId,
        /// Workflow the claim row fired.
        workflow_id: Uuid,
        /// Authoritative schedule instant, in Unix seconds.
        scheduled_for_unix_seconds: i64,
        /// Run the won claim created (`workflow_run_id`). `None` mirrors the
        /// row's not-yet-attached state: the claim cannot prove any run yet.
        workflow_run_id: Option<Uuid>,
    },
    /// The durable webhook invocation record, read from the invocation
    /// authority (owned by a later node) — never from the claimed delivery.
    /// It must retain every non-global binding needed to prove the invocation
    /// caused this run.
    Webhook {
        /// Tenant that owns the invocation record.
        community_id: CommunityId,
        /// Workflow the invocation fired.
        workflow_id: Uuid,
        /// Stable invocation UUID.
        invocation_id: Uuid,
        /// Run the invocation created. `None` mirrors a not-yet-attached
        /// record: the invocation cannot prove any run yet.
        workflow_run_id: Option<Uuid>,
    },
}

/// All independent inputs the caller fetched for one verification attempt.
#[derive(Clone, Debug, Default)]
pub struct FetchedAuthority<'a> {
    /// Exact signed kind-30620 definition revision, if fetched.
    pub definition: Option<&'a nostr::Event>,
    /// Exact relay-authored visible message, if fetched.
    pub message: Option<&'a nostr::Event>,
    /// Independent authority for the recorded cause, if fetched.
    pub cause: Option<CauseAuthority<'a>>,
}

// ---------------------------------------------------------------------------
// Tag helpers (extracted verbatim in behavior from the preserved #2737
// source: crates/buzz-acp/src/lib.rs @ 875769aaa).
// ---------------------------------------------------------------------------

fn exact_tags<'a>(event: &'a nostr::Event, name: &str) -> Vec<&'a nostr::Tag> {
    event
        .tags
        .iter()
        .filter(|tag| tag.as_slice().first().map(String::as_str) == Some(name))
        .collect()
}

fn event_channel_matches(event: &nostr::Event, channel_id: Uuid) -> bool {
    let channels = exact_tags(event, "h");
    channels.len() == 1
        && channels[0].as_slice().len() == 2
        && channels[0].as_slice()[1].parse::<Uuid>().ok() == Some(channel_id)
}

fn workflow_uuid(definition: &nostr::Event) -> Option<Uuid> {
    let tags = exact_tags(definition, "d");
    (tags.len() == 1 && tags[0].as_slice().len() == 2)
        .then(|| tags[0].as_slice()[1].parse().ok())
        .flatten()
}

// ---------------------------------------------------------------------------
// Wake authentication.
//
// Adopts the canonical identifier-only wake from B
// (`buzz_core::workflow_delivery::WorkflowDeliveryWake`): a wake names a
// delivery and a target, nothing else. Wakes are hints, never authority —
// every binding field is verified against signed authority by
// [`verify_workflow_delivery`], not against wake tags. This replaces the
// preserved #2737 full-binding-tuple wake grammar, which B's strict parse
// rejects by construction.
// ---------------------------------------------------------------------------

/// Authenticate and parse a relay-authored live wake before claiming.
///
/// Offline polling is the only path allowed to claim without an exact
/// delivery id. Returns the delivery identifier the wake names; the caller
/// must still cross-check the claimed delivery with
/// [`wake_references_delivery`] and fully verify it with
/// [`verify_workflow_delivery`].
pub fn trusted_live_workflow_wake_delivery_id(
    event: &nostr::Event,
    agent_pubkey: &str,
    relay_self: Option<&str>,
) -> Option<WorkflowDeliveryId> {
    let relay_self = relay_self?;
    if !event.pubkey.to_hex().eq_ignore_ascii_case(relay_self) || event.verify().is_err() {
        return None;
    }
    let wake = WorkflowDeliveryWake::parse(event).ok()?;
    wake.target_pubkey()
        .to_hex()
        .eq_ignore_ascii_case(agent_pubkey)
        .then(|| wake.delivery_id())
}

/// A claimed delivery must be the one the wake named, for the agent the wake
/// targeted. All other binding fields are the province of
/// [`verify_workflow_delivery`]; the identifier-only wake does not carry them.
pub fn wake_references_delivery(
    event: &nostr::Event,
    agent_pubkey: &str,
    relay_self: Option<&str>,
    delivery: &DeliverySnapshot,
) -> bool {
    trusted_live_workflow_wake_delivery_id(event, agent_pubkey, relay_self)
        .is_some_and(|delivery_id| delivery_id.as_uuid() == delivery.id)
        && delivery.target_pubkey.eq_ignore_ascii_case(agent_pubkey)
}

// ---------------------------------------------------------------------------
// Admission predicates (behavior preserved from #2737).
// ---------------------------------------------------------------------------

/// A relay-authored visible message declaring workflow shape.
pub fn is_workflow_delivery_candidate(event: &nostr::Event, relay_self: Option<&str>) -> bool {
    relay_self.is_some_and(|relay| {
        event.kind.as_u16() as u32 == KIND_STREAM_MESSAGE
            && event.pubkey.to_hex().eq_ignore_ascii_case(relay)
            && !exact_tags(event, "buzz:workflow").is_empty()
    })
}

/// Resolve the principal an inbound event is attributed to for author gating.
///
/// Workflow-shaped messages are admitted only with a durable verified owner;
/// an unclaimed workflow-shaped message fails closed.
pub fn workflow_delivery_principal(
    author: &str,
    durable_workflow_owner: Option<&str>,
    workflow_shape: bool,
) -> Option<String> {
    if durable_workflow_owner.is_none() && workflow_shape {
        return None;
    }
    Some(
        durable_workflow_owner
            .map(str::to_owned)
            .unwrap_or_else(|| author.to_owned()),
    )
}

// ---------------------------------------------------------------------------
// Core delivery verification.
// ---------------------------------------------------------------------------

/// Verify a claimed delivery against the exact signed authority it is bound
/// to. On success, returns the visible message together with the definition
/// owner (the principal the dispatch is attributed to).
///
/// Behavior matches `verified_workflow_delivery_message` from the preserved
/// #2737 source with three deliberate extensions:
///
/// 1. failures are typed ([`VerifyError`]) instead of flattened to `None`,
///    so transient unavailability can never be confused with forgery;
/// 2. the recorded canonical cause ([`WorkflowDeliveryCause`]) is actually
///    re-verified against independent caller-fetched authority
///    ([`CauseAuthority`]) for **every** cause class — signed event identity/
///    signature/channel for `Event`, the durable claim row's full binding
///    (tenant, workflow, slot, linked run) for `Schedule`, the durable
///    invocation record's full binding for `Webhook`. The
///    claimed delivery row is never its own proof; and
/// 3. the target must be admitted by the message's canonical `message-v1`
///    tags ([`message_v1_targets`]), never by an ordinary mention — the
///    consumer agrees narrowly with the producer's admission rule.
pub fn verify_workflow_delivery(
    delivery: &DeliverySnapshot,
    authority: &FetchedAuthority<'_>,
    agent_pubkey: &str,
    relay_self: Option<&str>,
) -> Result<(nostr::Event, String), VerifyError> {
    use buzz_workflow::executor::{resolve_template, TriggerContext};
    use buzz_workflow::schema::ActionDef;

    let relay_self = relay_self.ok_or(VerifyError::Unavailable(UnavailableKind::RelayIdentity))?;
    let definition = authority
        .definition
        .ok_or(VerifyError::Unavailable(UnavailableKind::Definition))?;
    let message = authority
        .message
        .ok_or(VerifyError::Unavailable(UnavailableKind::Message))?;

    // The caller fetched by id, but never trust the transport: re-check the
    // ids and signatures of everything we were handed.
    let definition_id = nostr::EventId::from_hex(&delivery.definition_event_id)
        .map_err(|_| VerifyError::Mismatch(MismatchKind::Definition))?;
    let message_id = nostr::EventId::from_hex(&delivery.message_event_id)
        .map_err(|_| VerifyError::Mismatch(MismatchKind::Message))?;
    if definition.id != definition_id || definition.verify().is_err() {
        return Err(VerifyError::Mismatch(MismatchKind::Definition));
    }
    if message.id != message_id || message.verify().is_err() {
        return Err(VerifyError::Mismatch(MismatchKind::Message));
    }

    if !delivery.target_pubkey.eq_ignore_ascii_case(agent_pubkey) {
        return Err(VerifyError::Mismatch(MismatchKind::Target));
    }
    let agent = nostr::PublicKey::from_hex(agent_pubkey)
        .map_err(|_| VerifyError::Mismatch(MismatchKind::Target))?;
    if definition.kind.as_u16() as u32 != KIND_WORKFLOW_DEF
        || workflow_uuid(definition) != Some(delivery.workflow_id)
        || !event_channel_matches(definition, delivery.channel_id)
    {
        return Err(VerifyError::Mismatch(MismatchKind::Definition));
    }
    // Canonical `message-v1` admission: the agent must be an explicitly
    // marked recipient. A malformed marker tag fails closed as a mismatch;
    // ordinary mentions never admit a durable delivery target.
    let admitted =
        message_v1_targets(message).map_err(|_| VerifyError::Mismatch(MismatchKind::Message))?;
    if message.kind.as_u16() as u32 != KIND_STREAM_MESSAGE
        || !event_channel_matches(message, delivery.channel_id)
        || !message.pubkey.to_hex().eq_ignore_ascii_case(relay_self)
        || !admitted.contains(&agent)
        || !exact_tags(message, "workflow-definition")
            .iter()
            .any(|tag| {
                tag.as_slice()
                    .get(1)
                    .is_some_and(|value| value.eq_ignore_ascii_case(&delivery.definition_event_id))
            })
        || !exact_tags(message, "workflow-run").iter().any(|tag| {
            tag.as_slice()
                .get(1)
                .is_some_and(|value| value == &delivery.run_id.to_string())
        })
        || !exact_tags(message, "workflow-step").iter().any(|tag| {
            tag.as_slice()
                .get(1)
                .is_some_and(|value| value == &delivery.step_id)
        })
    {
        return Err(VerifyError::Mismatch(MismatchKind::Message));
    }

    let (workflow, _) = buzz_workflow::WorkflowEngine::parse_yaml(&definition.content)
        .map_err(|_| VerifyError::Mismatch(MismatchKind::Step))?;
    let step = workflow
        .steps
        .iter()
        .find(|step| step.id == delivery.step_id)
        .ok_or(VerifyError::Mismatch(MismatchKind::Step))?;
    let ActionDef::SendMessage { text, channel, .. } = &step.action else {
        return Err(VerifyError::Mismatch(MismatchKind::Step));
    };
    if channel
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some_and(|value| value.parse::<Uuid>().ok() != Some(delivery.channel_id))
    {
        return Err(VerifyError::Mismatch(MismatchKind::Channel));
    }

    let raw_trigger = delivery
        .trigger_context
        .clone()
        .ok_or(VerifyError::Unavailable(UnavailableKind::TriggerContext))?;
    let trigger: TriggerContext = serde_json::from_value(raw_trigger)
        .map_err(|_| VerifyError::Unavailable(UnavailableKind::TriggerContext))?;
    if !trigger
        .definition_event_id
        .eq_ignore_ascii_case(&delivery.definition_event_id)
    {
        return Err(VerifyError::Mismatch(MismatchKind::Revision));
    }

    // Re-verify the recorded cause against independent authority. The claimed
    // delivery row is never its own proof: each cause class requires the
    // caller-fetched authority of the matching class — the exact signed event,
    // the durable schedule authority, or the durable webhook invocation
    // record. Absent authority is transient (`Unavailable`); disagreeing or
    // wrong-class authority is permanent (`Mismatch`).
    let cause_authority = authority
        .cause
        .ok_or(VerifyError::Unavailable(UnavailableKind::Cause))?;
    match (&delivery.cause, cause_authority) {
        (WorkflowDeliveryCause::Event(expected), CauseAuthority::Event(cause)) => {
            if cause.id != *expected
                || cause.verify().is_err()
                || !event_channel_matches(cause, delivery.channel_id)
            {
                return Err(VerifyError::Mismatch(MismatchKind::Cause));
            }
        }
        (
            WorkflowDeliveryCause::Schedule {
                scheduled_for_unix_seconds: recorded,
            },
            CauseAuthority::Schedule {
                community_id,
                workflow_id,
                scheduled_for_unix_seconds: authoritative,
                workflow_run_id,
            },
        ) => {
            // The claim row must bind this exact tenant, workflow, slot, and
            // the run it created. Two workflows can fire at the same second:
            // a same-slot row for another workflow (or another tenant, or one
            // linked to a different or not-yet-attached run) proves nothing
            // about this delivery.
            if community_id != delivery.community_id
                || workflow_id != delivery.workflow_id
                || authoritative != *recorded
                || workflow_run_id != Some(delivery.run_id)
            {
                return Err(VerifyError::Mismatch(MismatchKind::Cause));
            }
        }
        (
            WorkflowDeliveryCause::Webhook {
                invocation_id: recorded,
            },
            CauseAuthority::Webhook {
                community_id,
                workflow_id,
                invocation_id: authoritative,
                workflow_run_id,
            },
        ) => {
            // Same rule as Schedule: the durable invocation record must bind
            // tenant, workflow, exact invocation identity, and the run it
            // created — not merely re-present the delivery's scalar.
            if community_id != delivery.community_id
                || workflow_id != delivery.workflow_id
                || authoritative != *recorded
                || workflow_run_id != Some(delivery.run_id)
            {
                return Err(VerifyError::Mismatch(MismatchKind::Cause));
            }
        }
        // Authority of the wrong class can never validate this cause.
        _ => return Err(VerifyError::Mismatch(MismatchKind::Cause)),
    }

    let mut outputs = HashMap::new();
    let trace = delivery
        .execution_trace
        .as_array()
        .ok_or(VerifyError::Unavailable(UnavailableKind::ExecutionTrace))?;
    for entry in trace {
        let step_id = entry
            .get("step_id")
            .and_then(|value| value.as_str())
            .ok_or(VerifyError::Unavailable(UnavailableKind::ExecutionTrace))?;
        let output = entry
            .get("output")
            .cloned()
            .ok_or(VerifyError::Unavailable(UnavailableKind::ExecutionTrace))?;
        outputs.insert(step_id.to_string(), output);
    }
    let rendered = resolve_template(text, &trigger, &outputs)
        .map_err(|_| VerifyError::Mismatch(MismatchKind::Content))?;
    if message.content != rendered {
        return Err(VerifyError::Mismatch(MismatchKind::Content));
    }

    Ok((message.clone(), definition.pubkey.to_hex()))
}

// ---------------------------------------------------------------------------
// Tests. Pure and isolated: no network, no DB, no runtime.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_core::kind::KIND_WORKFLOW_AGENT_WAKE;
    use buzz_core::workflow_delivery::WORKFLOW_DELIVERY_TARGET_MARKER;
    use nostr::{EventBuilder, Keys, Kind, Tag};

    /// Sign a canonical identifier-only wake (or a malformed variant when
    /// `extra_tags` adds anything beyond the canonical pair).
    fn workflow_wake(
        signer: &Keys,
        target: &Keys,
        delivery_id: Uuid,
        extra_tags: impl IntoIterator<Item = Tag>,
    ) -> nostr::Event {
        let mut tags = vec![
            Tag::parse(["p", &target.public_key().to_hex()]).unwrap(),
            Tag::parse(["delivery", &delivery_id.to_string()]).unwrap(),
        ];
        tags.extend(extra_tags);
        EventBuilder::new(Kind::Custom(KIND_WORKFLOW_AGENT_WAKE as u16), "")
            .tags(tags)
            .sign_with_keys(signer)
            .unwrap()
    }

    /// Wake authentication preserved from #2737 in intent (relay authorship,
    /// signature, exact target, exact single identifier), re-expressed over
    /// B's canonical identifier-only wake grammar, which rejects any tag
    /// beyond the `p`/`delivery` pair by construction.
    #[test]
    fn live_workflow_wake_authentication_is_exact() {
        let relay = Keys::generate();
        let attacker = Keys::generate();
        let agent = Keys::generate();
        let delivery_id = Uuid::new_v4();
        let valid = workflow_wake(&relay, &agent, delivery_id, []);
        let authenticate = |event: &nostr::Event| {
            trusted_live_workflow_wake_delivery_id(
                event,
                &agent.public_key().to_hex(),
                Some(&relay.public_key().to_hex()),
            )
        };
        assert_eq!(
            authenticate(&valid).map(WorkflowDeliveryId::as_uuid),
            Some(delivery_id)
        );

        // Wake targeted at a different agent: not ours to claim.
        assert_eq!(
            trusted_live_workflow_wake_delivery_id(
                &valid,
                &attacker.public_key().to_hex(),
                Some(&relay.public_key().to_hex()),
            ),
            None
        );

        let forged_author = workflow_wake(&attacker, &agent, delivery_id, []);
        assert_eq!(authenticate(&forged_author), None);

        let mut invalid_signature = valid.clone();
        invalid_signature.content = "tampered".into();
        assert_eq!(authenticate(&invalid_signature), None);

        // Duplicate identifier tags and any tag outside the canonical
        // identifier-only grammar fail closed in the strict parse.
        let duplicate_delivery = workflow_wake(
            &relay,
            &agent,
            delivery_id,
            [Tag::parse(["delivery", &Uuid::new_v4().to_string()]).unwrap()],
        );
        assert_eq!(authenticate(&duplicate_delivery), None);
        let smuggled_binding = workflow_wake(
            &relay,
            &agent,
            delivery_id,
            [Tag::parse(["workflow-definition", &"11".repeat(32)]).unwrap()],
        );
        assert_eq!(authenticate(&smuggled_binding), None);
        let smuggled_channel = workflow_wake(
            &relay,
            &agent,
            delivery_id,
            [Tag::parse(["h", &Uuid::new_v4().to_string()]).unwrap()],
        );
        assert_eq!(authenticate(&smuggled_channel), None);

        // Non-UUID delivery identifier fails closed.
        let malformed = EventBuilder::new(Kind::Custom(KIND_WORKFLOW_AGENT_WAKE as u16), "")
            .tags([
                Tag::parse(["p", &agent.public_key().to_hex()]).unwrap(),
                Tag::parse(["delivery", "not-a-uuid"]).unwrap(),
            ])
            .sign_with_keys(&relay)
            .unwrap();
        assert_eq!(authenticate(&malformed), None);

        // Wrong kind fails closed.
        let wrong_kind = EventBuilder::new(Kind::Custom(KIND_STREAM_MESSAGE as u16), "")
            .tags([
                Tag::parse(["p", &agent.public_key().to_hex()]).unwrap(),
                Tag::parse(["delivery", &delivery_id.to_string()]).unwrap(),
            ])
            .sign_with_keys(&relay)
            .unwrap();
        assert_eq!(authenticate(&wrong_kind), None);

        // No relay identity: fail closed (Unavailable at the typed layer;
        // None here because wake auth precedes claiming).
        assert_eq!(
            trusted_live_workflow_wake_delivery_id(&valid, &agent.public_key().to_hex(), None),
            None
        );
    }

    /// Behavior-preservation test ported from #2737.
    #[test]
    fn only_verified_durable_workflow_messages_reach_dispatch() {
        assert_eq!(
            workflow_delivery_principal("relay", Some("durable-owner"), true),
            Some("durable-owner".to_owned())
        );
        assert!(
            workflow_delivery_principal("relay", None, true).is_none(),
            "an unclaimed workflow-shaped message must fail closed"
        );
        assert_eq!(
            workflow_delivery_principal("human", None, false),
            Some("human".to_owned()),
            "ordinary messages retain their author principal"
        );
    }

    /// Behavior-preservation test ported from #2737.
    #[test]
    fn unclaimed_workflow_messages_fail_closed_regardless_of_p_tags() {
        let relay = Keys::generate();
        let owner = Keys::generate().public_key().to_hex();
        let event = EventBuilder::new(Kind::Custom(KIND_STREAM_MESSAGE as u16), "visible")
            .tags([
                Tag::parse(["buzz:workflow", "message-v1"]).unwrap(),
                Tag::parse(["p", &owner]).unwrap(),
            ])
            .sign_with_keys(&relay)
            .unwrap();
        assert!(is_workflow_delivery_candidate(
            &event,
            Some(&relay.public_key().to_hex())
        ));
        assert!(workflow_delivery_principal("relay", None, true).is_none());
    }

    // -----------------------------------------------------------------------
    // Typed-verification fixtures.
    // -----------------------------------------------------------------------

    /// A one-field mutation of the delivery snapshot used by mutation tests.
    type Mutation = Box<dyn Fn(&mut DeliverySnapshot)>;

    struct Fixture {
        relay: Keys,
        owner: Keys,
        agent: Keys,
        channel: Uuid,
        invocation_id: Uuid,
        definition: nostr::Event,
        message: nostr::Event,
        delivery: DeliverySnapshot,
    }

    fn fixture() -> Fixture {
        let relay = Keys::generate();
        let owner = Keys::generate();
        let agent = Keys::generate();
        let channel = Uuid::new_v4();
        let workflow_id = Uuid::new_v4();
        let run_id = Uuid::new_v4();
        let definition = EventBuilder::new(
            Kind::Custom(KIND_WORKFLOW_DEF as u16),
            "name: signed\ntrigger:\n  on: webhook\nsteps:\n  - id: call\n    action: send_message\n    text: prior\n  - id: wake\n    action: send_message\n    text: 'status {{steps.call.output.body}}'\n",
        )
        .tags([
            Tag::parse(["d", &workflow_id.to_string()]).unwrap(),
            Tag::parse(["h", &channel.to_string()]).unwrap(),
        ])
        .sign_with_keys(&owner)
        .unwrap();
        let message = EventBuilder::new(Kind::Custom(KIND_STREAM_MESSAGE as u16), "status durable")
            .tags([
                Tag::parse(["h", &channel.to_string()]).unwrap(),
                // Canonical four-field `message-v1` marker tag: the only tag
                // shape that admits a durable delivery target.
                Tag::parse([
                    "p",
                    &agent.public_key().to_hex(),
                    "",
                    WORKFLOW_DELIVERY_TARGET_MARKER,
                ])
                .unwrap(),
                Tag::parse(["workflow-definition", &definition.id.to_hex()]).unwrap(),
                Tag::parse(["workflow-run", &run_id.to_string()]).unwrap(),
                Tag::parse(["workflow-step", "wake"]).unwrap(),
            ])
            .sign_with_keys(&relay)
            .unwrap();
        let trigger = buzz_workflow::executor::TriggerContext {
            channel_id: channel.to_string(),
            definition_event_id: definition.id.to_hex(),
            ..Default::default()
        };
        let trigger_json = serde_json::to_value(trigger).unwrap();
        let community_id = CommunityId::from_uuid(Uuid::new_v4());
        let invocation_id = Uuid::new_v4();
        let delivery = DeliverySnapshot {
            id: Uuid::new_v4(),
            community_id,
            workflow_id,
            run_id,
            step_id: "wake".to_string(),
            definition_event_id: definition.id.to_hex(),
            message_event_id: message.id.to_hex(),
            channel_id: channel,
            target_pubkey: agent.public_key().to_hex(),
            cause: WorkflowDeliveryCause::Webhook { invocation_id },
            execution_trace: serde_json::json!([{
                "step_id": "call",
                "output": {"body": "durable"}
            }]),
            trigger_context: Some(trigger_json),
        };
        Fixture {
            relay,
            owner,
            agent,
            channel,
            invocation_id,
            definition,
            message,
            delivery,
        }
    }

    /// Verify against the fixture's authority, supplying the durable webhook
    /// invocation record binding that matches the fixture delivery's cause.
    fn verify(
        f: &Fixture,
        delivery: &DeliverySnapshot,
    ) -> Result<(nostr::Event, String), VerifyError> {
        verify_workflow_delivery(
            delivery,
            &FetchedAuthority {
                definition: Some(&f.definition),
                message: Some(&f.message),
                cause: Some(CauseAuthority::Webhook {
                    community_id: f.delivery.community_id,
                    workflow_id: f.delivery.workflow_id,
                    invocation_id: f.invocation_id,
                    workflow_run_id: Some(f.delivery.run_id),
                }),
            },
            &f.agent.public_key().to_hex(),
            Some(&f.relay.public_key().to_hex()),
        )
    }

    /// Port of `durable_claim_reconstructs_prior_output_and_rejects_mutable_bindings`
    /// (behavior preserved; REST fetch replaced by supplied authority).
    #[test]
    fn durable_claim_reconstructs_prior_output_and_rejects_mutable_bindings() {
        let f = fixture();
        let verified =
            verify(&f, &f.delivery).expect("durable trace reconstructs prior-step template");
        assert_eq!(verified.0.content, "status durable");
        assert_eq!(verified.1, f.owner.public_key().to_hex());

        // Mutation cases: flip exactly one binding field, expect Mismatch —
        // never Unavailable, never success. Proves every field is load-bearing.
        let cases: Vec<(&str, Mutation, MismatchKind)> = vec![
            (
                "workflow_id",
                Box::new(|d| d.workflow_id = Uuid::new_v4()),
                MismatchKind::Definition,
            ),
            (
                "run_id",
                Box::new(|d| d.run_id = Uuid::new_v4()),
                MismatchKind::Message,
            ),
            (
                "step_id",
                Box::new(|d| d.step_id = "call".into()),
                MismatchKind::Message,
            ),
            (
                "channel_id",
                Box::new(|d| d.channel_id = Uuid::new_v4()),
                MismatchKind::Definition,
            ),
        ];
        for (name, mutate, expected) in cases {
            let mut mutated = f.delivery.clone();
            mutate(&mut mutated);
            assert_eq!(
                verify(&f, &mutated),
                Err(VerifyError::Mismatch(expected.clone())),
                "mutated binding field `{name}` must be a permanent mismatch"
            );
        }

        // Target mutation.
        let mut wrong_target = f.delivery.clone();
        wrong_target.target_pubkey = f.owner.public_key().to_hex();
        assert_eq!(
            verify(&f, &wrong_target),
            Err(VerifyError::Mismatch(MismatchKind::Target))
        );

        // Swapped event ids: the supplied authority no longer matches.
        let mut swapped_definition = f.delivery.clone();
        swapped_definition.definition_event_id = f.message.id.to_hex();
        assert_eq!(
            verify(&f, &swapped_definition),
            Err(VerifyError::Mismatch(MismatchKind::Definition))
        );
        let mut swapped_message = f.delivery.clone();
        swapped_message.message_event_id = f.definition.id.to_hex();
        assert_eq!(
            verify(&f, &swapped_message),
            Err(VerifyError::Mismatch(MismatchKind::Message))
        );
    }

    #[test]
    fn tampered_supplied_authority_is_a_permanent_mismatch() {
        let f = fixture();

        let mut tampered_definition = f.definition.clone();
        tampered_definition.content = "name: forged\nsteps: []\n".into();
        assert_eq!(
            verify_workflow_delivery(
                &f.delivery,
                &FetchedAuthority {
                    definition: Some(&tampered_definition),
                    message: Some(&f.message),
                    cause: None,
                },
                &f.agent.public_key().to_hex(),
                Some(&f.relay.public_key().to_hex()),
            ),
            Err(VerifyError::Mismatch(MismatchKind::Definition))
        );

        let mut tampered_message = f.message.clone();
        tampered_message.content = "forged visible content".into();
        assert_eq!(
            verify_workflow_delivery(
                &f.delivery,
                &FetchedAuthority {
                    definition: Some(&f.definition),
                    message: Some(&tampered_message),
                    cause: None,
                },
                &f.agent.public_key().to_hex(),
                Some(&f.relay.public_key().to_hex()),
            ),
            Err(VerifyError::Mismatch(MismatchKind::Message))
        );

        // Rendered-content forgery: correctly signed relay message whose
        // content disagrees with the deterministic template render.
        let forged_render =
            EventBuilder::new(Kind::Custom(KIND_STREAM_MESSAGE as u16), "status FORGED")
                .tags(f.message.tags.to_vec())
                .sign_with_keys(&f.relay)
                .unwrap();
        let mut delivery = f.delivery.clone();
        delivery.message_event_id = forged_render.id.to_hex();
        assert_eq!(
            verify_workflow_delivery(
                &delivery,
                &FetchedAuthority {
                    definition: Some(&f.definition),
                    message: Some(&forged_render),
                    // Content is checked after the cause gate; supply the
                    // matching cause authority so the render forgery is what
                    // fails.
                    cause: Some(CauseAuthority::Webhook {
                        community_id: f.delivery.community_id,
                        workflow_id: f.delivery.workflow_id,
                        invocation_id: f.invocation_id,
                        workflow_run_id: Some(f.delivery.run_id),
                    }),
                },
                &f.agent.public_key().to_hex(),
                Some(&f.relay.public_key().to_hex()),
            ),
            Err(VerifyError::Mismatch(MismatchKind::Content))
        );
    }

    #[test]
    fn ordinary_mentions_never_admit_a_delivery_target() {
        let f = fixture();
        // Identical message except the agent is a plain two-field mention,
        // not a canonical four-field `message-v1` marker tag.
        let mention_only =
            EventBuilder::new(Kind::Custom(KIND_STREAM_MESSAGE as u16), "status durable")
                .tags([
                    Tag::parse(["h", &f.channel.to_string()]).unwrap(),
                    Tag::parse(["p", &f.agent.public_key().to_hex()]).unwrap(),
                    Tag::parse(["workflow-definition", &f.definition.id.to_hex()]).unwrap(),
                    Tag::parse(["workflow-run", &f.delivery.run_id.to_string()]).unwrap(),
                    Tag::parse(["workflow-step", "wake"]).unwrap(),
                ])
                .sign_with_keys(&f.relay)
                .unwrap();
        let mut delivery = f.delivery.clone();
        delivery.message_event_id = mention_only.id.to_hex();
        assert_eq!(
            verify_workflow_delivery(
                &delivery,
                &FetchedAuthority {
                    definition: Some(&f.definition),
                    message: Some(&mention_only),
                    cause: None,
                },
                &f.agent.public_key().to_hex(),
                Some(&f.relay.public_key().to_hex()),
            ),
            Err(VerifyError::Mismatch(MismatchKind::Message))
        );
    }

    #[test]
    fn missing_inputs_are_transient_not_mismatches() {
        let f = fixture();

        assert_eq!(
            verify_workflow_delivery(
                &f.delivery,
                &FetchedAuthority {
                    definition: None,
                    message: Some(&f.message),
                    cause: None,
                },
                &f.agent.public_key().to_hex(),
                Some(&f.relay.public_key().to_hex()),
            ),
            Err(VerifyError::Unavailable(UnavailableKind::Definition))
        );
        assert_eq!(
            verify_workflow_delivery(
                &f.delivery,
                &FetchedAuthority {
                    definition: Some(&f.definition),
                    message: None,
                    cause: None,
                },
                &f.agent.public_key().to_hex(),
                Some(&f.relay.public_key().to_hex()),
            ),
            Err(VerifyError::Unavailable(UnavailableKind::Message))
        );
        assert_eq!(
            verify(&f, &f.delivery).ok().map(|_| ()),
            Some(()),
            "control: unmutated fixture verifies"
        );

        let mut no_trigger = f.delivery.clone();
        no_trigger.trigger_context = None;
        assert_eq!(
            verify(&f, &no_trigger),
            Err(VerifyError::Unavailable(UnavailableKind::TriggerContext))
        );

        let mut no_trace = f.delivery.clone();
        no_trace.execution_trace = serde_json::json!({});
        assert_eq!(
            verify(&f, &no_trace),
            Err(VerifyError::Unavailable(UnavailableKind::ExecutionTrace))
        );

        assert_eq!(
            verify_workflow_delivery(
                &f.delivery,
                &FetchedAuthority {
                    definition: Some(&f.definition),
                    message: Some(&f.message),
                    cause: None,
                },
                &f.agent.public_key().to_hex(),
                None,
            ),
            Err(VerifyError::Unavailable(UnavailableKind::RelayIdentity))
        );
    }

    #[test]
    fn signed_causes_are_reverified_not_trusted() {
        let f = fixture();
        let author = Keys::generate();
        let cause_event = EventBuilder::new(Kind::Custom(KIND_STREAM_MESSAGE as u16), "trigger me")
            .tags([Tag::parse(["h", &f.channel.to_string()]).unwrap()])
            .sign_with_keys(&author)
            .unwrap();

        let with_cause = |cause: WorkflowDeliveryCause| {
            let mut delivery = f.delivery.clone();
            delivery.cause = cause;
            delivery
        };

        // Recorded signed cause + matching supplied event: verifies.
        let delivery = with_cause(WorkflowDeliveryCause::Event(cause_event.id));
        assert!(verify_workflow_delivery(
            &delivery,
            &FetchedAuthority {
                definition: Some(&f.definition),
                message: Some(&f.message),
                cause: Some(CauseAuthority::Event(&cause_event)),
            },
            &f.agent.public_key().to_hex(),
            Some(&f.relay.public_key().to_hex()),
        )
        .is_ok());

        // Recorded signed cause but no supplied event: transient, not dispatch.
        assert_eq!(
            verify_workflow_delivery(
                &delivery,
                &FetchedAuthority {
                    definition: Some(&f.definition),
                    message: Some(&f.message),
                    cause: None,
                },
                &f.agent.public_key().to_hex(),
                Some(&f.relay.public_key().to_hex()),
            ),
            Err(VerifyError::Unavailable(UnavailableKind::Cause))
        );

        // Wrong cause event supplied: permanent mismatch.
        let unrelated = EventBuilder::new(Kind::Custom(KIND_STREAM_MESSAGE as u16), "unrelated")
            .tags([Tag::parse(["h", &f.channel.to_string()]).unwrap()])
            .sign_with_keys(&author)
            .unwrap();
        assert_eq!(
            verify_workflow_delivery(
                &delivery,
                &FetchedAuthority {
                    definition: Some(&f.definition),
                    message: Some(&f.message),
                    cause: Some(CauseAuthority::Event(&unrelated)),
                },
                &f.agent.public_key().to_hex(),
                Some(&f.relay.public_key().to_hex()),
            ),
            Err(VerifyError::Mismatch(MismatchKind::Cause))
        );

        // Tampered cause event (invalid signature): permanent mismatch.
        let mut tampered = cause_event.clone();
        tampered.content = "forged".into();
        assert_eq!(
            verify_workflow_delivery(
                &delivery,
                &FetchedAuthority {
                    definition: Some(&f.definition),
                    message: Some(&f.message),
                    cause: Some(CauseAuthority::Event(&tampered)),
                },
                &f.agent.public_key().to_hex(),
                Some(&f.relay.public_key().to_hex()),
            ),
            Err(VerifyError::Mismatch(MismatchKind::Cause))
        );

        // Cause from a different channel: permanent mismatch.
        let foreign = EventBuilder::new(Kind::Custom(KIND_STREAM_MESSAGE as u16), "trigger me")
            .tags([Tag::parse(["h", &Uuid::new_v4().to_string()]).unwrap()])
            .sign_with_keys(&author)
            .unwrap();
        let foreign_delivery = with_cause(WorkflowDeliveryCause::Event(foreign.id));
        assert_eq!(
            verify_workflow_delivery(
                &foreign_delivery,
                &FetchedAuthority {
                    definition: Some(&f.definition),
                    message: Some(&f.message),
                    cause: Some(CauseAuthority::Event(&foreign)),
                },
                &f.agent.public_key().to_hex(),
                Some(&f.relay.public_key().to_hex()),
            ),
            Err(VerifyError::Mismatch(MismatchKind::Cause))
        );

        // Unsigned cause classes carry no signed artifact, but they are not
        // self-proving either: each requires the durable authority of its
        // own class, exercised in `unsigned_causes_require_durable_authority`.
    }

    /// Schedule and webhook causes are re-established from durable authority
    /// carrying the source row's full binding identity — the claimed delivery
    /// row is never its own proof, and a same-slot row for another workflow,
    /// tenant, or run proves nothing. Absent authority is transient;
    /// disagreeing, unbound, or wrong-class authority is permanent.
    #[test]
    fn unsigned_causes_require_durable_authority() {
        let f = fixture();
        let agent_hex = f.agent.public_key().to_hex();
        let relay_hex = f.relay.public_key().to_hex();
        let verify_with = |delivery: &DeliverySnapshot, cause: Option<CauseAuthority<'_>>| {
            verify_workflow_delivery(
                delivery,
                &FetchedAuthority {
                    definition: Some(&f.definition),
                    message: Some(&f.message),
                    cause,
                },
                &agent_hex,
                Some(&relay_hex),
            )
        };
        let with_cause = |cause: WorkflowDeliveryCause| {
            let mut delivery = f.delivery.clone();
            delivery.cause = cause;
            delivery
        };
        let expect_mismatch = |result: Result<(nostr::Event, String), VerifyError>, name: &str| {
            assert_eq!(
                result,
                Err(VerifyError::Mismatch(MismatchKind::Cause)),
                "{name} must be a permanent cause mismatch"
            );
        };

        // --- Schedule ---
        let slot = 1_787_680_000_i64;
        let schedule = with_cause(WorkflowDeliveryCause::Schedule {
            scheduled_for_unix_seconds: slot,
        });
        let exact_row = CauseAuthority::Schedule {
            community_id: f.delivery.community_id,
            workflow_id: f.delivery.workflow_id,
            scheduled_for_unix_seconds: slot,
            workflow_run_id: Some(f.delivery.run_id),
        };
        // Control: the exact matching durable claim row verifies.
        assert!(verify_with(&schedule, Some(exact_row)).is_ok());
        // One-field mutations of the row binding: each proves the row did not
        // cause this delivery.
        expect_mismatch(
            verify_with(
                &schedule,
                Some(CauseAuthority::Schedule {
                    community_id: CommunityId::from_uuid(Uuid::new_v4()),
                    workflow_id: f.delivery.workflow_id,
                    scheduled_for_unix_seconds: slot,
                    workflow_run_id: Some(f.delivery.run_id),
                }),
            ),
            "schedule row from a different community",
        );
        expect_mismatch(
            verify_with(
                &schedule,
                Some(CauseAuthority::Schedule {
                    community_id: f.delivery.community_id,
                    workflow_id: Uuid::new_v4(),
                    scheduled_for_unix_seconds: slot,
                    workflow_run_id: Some(f.delivery.run_id),
                }),
            ),
            "same-slot schedule row for a different workflow",
        );
        expect_mismatch(
            verify_with(
                &schedule,
                Some(CauseAuthority::Schedule {
                    community_id: f.delivery.community_id,
                    workflow_id: f.delivery.workflow_id,
                    scheduled_for_unix_seconds: slot + 1,
                    workflow_run_id: Some(f.delivery.run_id),
                }),
            ),
            "schedule row for a different slot",
        );
        expect_mismatch(
            verify_with(
                &schedule,
                Some(CauseAuthority::Schedule {
                    community_id: f.delivery.community_id,
                    workflow_id: f.delivery.workflow_id,
                    scheduled_for_unix_seconds: slot,
                    workflow_run_id: Some(Uuid::new_v4()),
                }),
            ),
            "same-workflow schedule row linked to a different run",
        );
        expect_mismatch(
            verify_with(
                &schedule,
                Some(CauseAuthority::Schedule {
                    community_id: f.delivery.community_id,
                    workflow_id: f.delivery.workflow_id,
                    scheduled_for_unix_seconds: slot,
                    workflow_run_id: None,
                }),
            ),
            "schedule row with no attached run",
        );
        // Mutated recorded slot against the exact row: permanent mismatch.
        expect_mismatch(
            verify_with(
                &with_cause(WorkflowDeliveryCause::Schedule {
                    scheduled_for_unix_seconds: slot + 1,
                }),
                Some(exact_row),
            ),
            "delivery recording a different slot than the durable row",
        );
        // Dropped durable authority: transient, not dispatch.
        assert_eq!(
            verify_with(&schedule, None),
            Err(VerifyError::Unavailable(UnavailableKind::Cause))
        );

        // --- Webhook (same binding rule) ---
        // Control: the fixture delivery's webhook cause with its matching
        // durable invocation record binding.
        assert!(verify(&f, &f.delivery).is_ok());
        let webhook_with = |community_id: CommunityId,
                            workflow_id: Uuid,
                            invocation_id: Uuid,
                            workflow_run_id: Option<Uuid>| {
            CauseAuthority::Webhook {
                community_id,
                workflow_id,
                invocation_id,
                workflow_run_id,
            }
        };
        expect_mismatch(
            verify_with(
                &f.delivery,
                Some(webhook_with(
                    CommunityId::from_uuid(Uuid::new_v4()),
                    f.delivery.workflow_id,
                    f.invocation_id,
                    Some(f.delivery.run_id),
                )),
            ),
            "invocation record from a different community",
        );
        expect_mismatch(
            verify_with(
                &f.delivery,
                Some(webhook_with(
                    f.delivery.community_id,
                    Uuid::new_v4(),
                    f.invocation_id,
                    Some(f.delivery.run_id),
                )),
            ),
            "invocation record for a different workflow",
        );
        expect_mismatch(
            verify_with(
                &f.delivery,
                Some(webhook_with(
                    f.delivery.community_id,
                    f.delivery.workflow_id,
                    Uuid::new_v4(),
                    Some(f.delivery.run_id),
                )),
            ),
            "different invocation identity",
        );
        expect_mismatch(
            verify_with(
                &f.delivery,
                Some(webhook_with(
                    f.delivery.community_id,
                    f.delivery.workflow_id,
                    f.invocation_id,
                    Some(Uuid::new_v4()),
                )),
            ),
            "invocation record linked to a different run",
        );
        expect_mismatch(
            verify_with(
                &f.delivery,
                Some(webhook_with(
                    f.delivery.community_id,
                    f.delivery.workflow_id,
                    f.invocation_id,
                    None,
                )),
            ),
            "invocation record with no attached run",
        );
        // Mutated recorded invocation id against the exact record.
        expect_mismatch(
            verify(
                &f,
                &with_cause(WorkflowDeliveryCause::Webhook {
                    invocation_id: Uuid::new_v4(),
                }),
            ),
            "delivery recording a different invocation than the durable record",
        );
        // Dropped durable authority: transient, not dispatch.
        assert_eq!(
            verify_with(&f.delivery, None),
            Err(VerifyError::Unavailable(UnavailableKind::Cause))
        );

        // --- Wrong-class authority can never validate a cause ---
        // Schedule cause + webhook authority.
        expect_mismatch(
            verify(&f, &schedule),
            "schedule cause with webhook authority",
        );
        // Webhook cause + schedule authority.
        expect_mismatch(
            verify_with(&f.delivery, Some(exact_row)),
            "webhook cause with schedule authority",
        );
        // Event cause + webhook authority.
        let cause_event = EventBuilder::new(Kind::Custom(KIND_STREAM_MESSAGE as u16), "trigger")
            .tags([Tag::parse(["h", &f.channel.to_string()]).unwrap()])
            .sign_with_keys(&Keys::generate())
            .unwrap();
        expect_mismatch(
            verify(
                &f,
                &with_cause(WorkflowDeliveryCause::Event(cause_event.id)),
            ),
            "event cause with webhook authority",
        );
    }

    #[test]
    fn wake_and_delivery_must_agree_on_identity() {
        let f = fixture();
        let wake = workflow_wake(&f.relay, &f.agent, f.delivery.id, []);
        let agent_hex = f.agent.public_key().to_hex();
        let relay_hex = f.relay.public_key().to_hex();
        assert!(wake_references_delivery(
            &wake,
            &agent_hex,
            Some(&relay_hex),
            &f.delivery
        ));

        // The identifier-only wake binds delivery id and target; flip each.
        let mutations: Vec<Mutation> = vec![
            Box::new(|d| d.id = Uuid::new_v4()),
            Box::new(|d| d.target_pubkey = "55".repeat(32)),
        ];
        for (i, mutate) in mutations.iter().enumerate() {
            let mut mutated = f.delivery.clone();
            mutate(&mut mutated);
            assert!(
                !wake_references_delivery(&wake, &agent_hex, Some(&relay_hex), &mutated),
                "wake/delivery disagreement on mutation {i} must fail closed"
            );
        }

        // Every other binding field is verified against signed authority, not
        // wake tags: a mutated snapshot may pass the identifier cross-check
        // but must then fail closed in full verification.
        let mut mutated = f.delivery.clone();
        mutated.run_id = Uuid::new_v4();
        assert!(wake_references_delivery(
            &wake,
            &agent_hex,
            Some(&relay_hex),
            &mutated
        ));
        assert_eq!(
            verify(&f, &mutated),
            Err(VerifyError::Mismatch(MismatchKind::Message))
        );
    }
}
