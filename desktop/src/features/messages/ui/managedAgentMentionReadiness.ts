import { applyManagedAgentAccessPolicy } from "@/features/agents/lib/managedAgentAccessPolicy";
import type { AgentPersona, ManagedAgent } from "@/shared/api/types";
import { normalizePubkey } from "@/shared/lib/pubkey";
import {
  getErrorMessage,
  isManagedAgentRunning,
  isProviderBackedAgent,
  uniqueNormalizedPubkeys,
} from "./useMentionSendFlow.helpers";

type AttachAgentInput = {
  channelId: string;
  agent: ManagedAgent;
  role: "bot";
};

export type PrepareManagedAgentMentionsInput = {
  mentionPubkeys: readonly string[];
  channelId: string;
  managedAgents: Iterable<ManagedAgent>;
  personas: Iterable<
    Pick<AgentPersona, "id" | "respondTo" | "respondToAllowlist">
  >;
  participantPubkeys?: Iterable<string>;
  newlyAddedParticipantPubkeys?: Iterable<string>;
  attachAgent: (input: AttachAgentInput) => Promise<unknown>;
  startAgent: (pubkey: string) => Promise<unknown>;
};

/** Prepares already-managed identities selected by the message composer. */
export async function prepareManagedAgentMentionsForChannel({
  mentionPubkeys,
  channelId,
  managedAgents,
  personas,
  participantPubkeys = [],
  newlyAddedParticipantPubkeys = [],
  attachAgent,
  startAgent,
}: PrepareManagedAgentMentionsInput) {
  if (!channelId || mentionPubkeys.length === 0) {
    return { errors: [] as string[], pubkeys: [] as string[] };
  }

  const managedAgentsByPubkey = new Map(
    [...managedAgents].map((agent) => [normalizePubkey(agent.pubkey), agent]),
  );
  const personasById = new Map(
    [...personas].map((persona) => [persona.id, persona]),
  );
  const participants = new Set(
    [...participantPubkeys].map((pubkey) => normalizePubkey(pubkey)),
  );
  const newlyAddedParticipants = new Set(
    [...newlyAddedParticipantPubkeys].map((pubkey) => normalizePubkey(pubkey)),
  );
  const errors: string[] = [];
  const pubkeys: string[] = [];

  for (const pubkey of uniqueNormalizedPubkeys(mentionPubkeys)) {
    const agent = managedAgentsByPubkey.get(pubkey);
    if (!agent) {
      continue;
    }

    try {
      const definition = agent.personaId
        ? personasById.get(agent.personaId)
        : undefined;
      const policyAgent =
        !participants.has(pubkey) || newlyAddedParticipants.has(pubkey)
          ? await applyManagedAgentAccessPolicy(agent, {}, definition)
          : agent;

      if (participants.has(pubkey)) {
        if (isProviderBackedAgent(policyAgent)) {
          if (policyAgent.status !== "deployed") {
            await startAgent(policyAgent.pubkey);
          }
        } else if (!isManagedAgentRunning(policyAgent)) {
          await startAgent(policyAgent.pubkey);
        }
      } else {
        await attachAgent({
          channelId,
          agent: policyAgent,
          role: "bot",
        });
      }
      pubkeys.push(pubkey);
    } catch (error) {
      errors.push(
        `${agent.name}: ${getErrorMessage(error, "Could not prepare agent.")}`,
      );
    }
  }

  return {
    errors,
    pubkeys: uniqueNormalizedPubkeys(pubkeys),
  };
}
