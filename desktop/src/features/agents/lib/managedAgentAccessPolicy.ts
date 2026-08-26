import { updateManagedAgent } from "@/shared/api/tauri";
import type {
  AgentPersona,
  ManagedAgent,
  RespondToMode,
} from "@/shared/api/types";

export type AgentAccessPolicyDefinition = Pick<
  AgentPersona,
  "id" | "respondTo" | "respondToAllowlist"
>;

export type AgentAccessPolicyRequest = {
  respondTo?: RespondToMode | null;
  respondToAllowlist?: readonly string[];
};

export type ResolvedAgentAccessPolicy = {
  respondTo: RespondToMode;
  respondToAllowlist: string[];
};

/** Uses the same mode and allowlist precedence as backend agent creation. */
export function resolveManagedAgentAccessPolicy(
  request: AgentAccessPolicyRequest,
  definition?: AgentAccessPolicyDefinition,
): ResolvedAgentAccessPolicy {
  const requestedAllowlist = [...(request.respondToAllowlist ?? [])];

  if (request.respondTo != null) {
    return {
      respondTo: request.respondTo,
      respondToAllowlist: requestedAllowlist,
    };
  }

  if (definition?.respondTo != null) {
    return {
      respondTo: definition.respondTo,
      respondToAllowlist:
        requestedAllowlist.length > 0
          ? requestedAllowlist
          : [...definition.respondToAllowlist],
    };
  }

  return {
    respondTo: "owner-only",
    respondToAllowlist: requestedAllowlist,
  };
}

export async function applyManagedAgentAccessPolicy(
  agent: ManagedAgent,
  request: AgentAccessPolicyRequest,
  definition?: AgentAccessPolicyDefinition,
): Promise<ManagedAgent> {
  const policy = resolveManagedAgentAccessPolicy(request, definition);
  const allowlistMatches =
    agent.respondToAllowlist.length === policy.respondToAllowlist.length &&
    agent.respondToAllowlist.every(
      (pubkey, index) => pubkey === policy.respondToAllowlist[index],
    );

  if (agent.respondTo === policy.respondTo && allowlistMatches) {
    return agent;
  }

  return (
    await updateManagedAgent({
      pubkey: agent.pubkey,
      respondTo: policy.respondTo,
      respondToAllowlist: policy.respondToAllowlist,
    })
  ).agent;
}
