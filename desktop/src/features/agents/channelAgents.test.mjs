import assert from "node:assert/strict";
import test from "node:test";

import { provisionChannelManagedAgent } from "./channelAgents.ts";
import { prepareManagedAgentMentionsForChannel } from "../messages/ui/managedAgentMentionReadiness.ts";

const PUBKEY = "a".repeat(64);
const ALLOWED_PUBKEY = "b".repeat(64);
const RUNTIME = {
  id: "goose",
  label: "Goose",
  command: "goose",
  defaultArgs: [],
  mcpCommand: "buzz-dev-mcp",
};

function makeAgent(personaId, overrides = {}) {
  return {
    pubkey: PUBKEY,
    name: "reviewer",
    personaId,
    runtime: null,
    teamId: null,
    relayUrl: "wss://relay.example",
    acpCommand: "buzz-acp",
    agentCommand: "goose",
    agentCommandOverride: null,
    agentArgs: [],
    mcpCommand: "buzz-dev-mcp",
    turnTimeoutSeconds: 320,
    idleTimeoutSeconds: null,
    maxTurnDurationSeconds: null,
    parallelism: 1,
    systemPrompt: null,
    avatarUrl: null,
    model: null,
    modelSource: null,
    provider: null,
    personaOutOfDate: false,
    personaOrphaned: false,
    needsRestart: false,
    restartDiff: [],
    envVars: {},
    status: "running",
    pid: null,
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
    lastStartedAt: null,
    lastStoppedAt: null,
    lastExitCode: null,
    lastError: null,
    lastErrorCode: null,
    logPath: "",
    startOnAppLaunch: false,
    autoRestartOnConfigChange: true,
    backend: { type: "local" },
    backendAgentId: null,
    respondTo: "anyone",
    respondToAllowlist: [PUBKEY],
    ...overrides,
  };
}

function toRawAgent(agent) {
  return {
    pubkey: agent.pubkey,
    name: agent.name,
    persona_id: agent.personaId,
    runtime: agent.runtime,
    team_id: agent.teamId,
    relay_url: agent.relayUrl,
    acp_command: agent.acpCommand,
    agent_command: agent.agentCommand,
    agent_command_override: agent.agentCommandOverride,
    agent_args: agent.agentArgs,
    mcp_command: agent.mcpCommand,
    turn_timeout_seconds: agent.turnTimeoutSeconds,
    idle_timeout_seconds: agent.idleTimeoutSeconds,
    max_turn_duration_seconds: agent.maxTurnDurationSeconds,
    parallelism: agent.parallelism,
    system_prompt: agent.systemPrompt,
    avatar_url: agent.avatarUrl,
    model: agent.model,
    model_source: agent.modelSource,
    provider: agent.provider,
    persona_out_of_date: agent.personaOutOfDate,
    persona_orphaned: agent.personaOrphaned,
    needs_restart: agent.needsRestart,
    restart_diff: agent.restartDiff,
    env_vars: agent.envVars,
    status: agent.status,
    pid: agent.pid,
    created_at: agent.createdAt,
    updated_at: agent.updatedAt,
    last_started_at: agent.lastStartedAt,
    last_stopped_at: agent.lastStoppedAt,
    last_exit_code: agent.lastExitCode,
    last_error: agent.lastError,
    last_error_code: agent.lastErrorCode,
    log_path: agent.logPath,
    start_on_app_launch: agent.startOnAppLaunch,
    auto_restart_on_config_change: agent.autoRestartOnConfigChange,
    backend: agent.backend,
    backend_agent_id: agent.backendAgentId,
    respond_to: agent.respondTo,
    respond_to_allowlist: agent.respondToAllowlist,
  };
}

test("reuse applies explicit, persona, and owner-only access policies", async (t) => {
  const priorWindow = globalThis.window;
  t.after(() => {
    globalThis.window = priorWindow;
  });

  const scenarios = [
    {
      label: "generic default",
      personaId: null,
      personas: [],
      request: {},
      expectedMode: "owner-only",
      expectedAllowlist: [],
    },
    {
      label: "persona unset default",
      personaId: "persona-owner",
      personas: [
        {
          id: "persona-owner",
          respondTo: null,
          respondToAllowlist: [],
        },
      ],
      request: {},
      expectedMode: "owner-only",
      expectedAllowlist: [],
    },
    {
      label: "persona anyone",
      personaId: "persona-anyone",
      personas: [
        {
          id: "persona-anyone",
          respondTo: "anyone",
          respondToAllowlist: [ALLOWED_PUBKEY],
        },
      ],
      request: {},
      expectedMode: "anyone",
      expectedAllowlist: [ALLOWED_PUBKEY],
    },
    {
      label: "persona allowlist",
      personaId: "persona-allowlist",
      personas: [
        {
          id: "persona-allowlist",
          respondTo: "allowlist",
          respondToAllowlist: [ALLOWED_PUBKEY],
        },
      ],
      request: {},
      expectedMode: "allowlist",
      expectedAllowlist: [ALLOWED_PUBKEY],
    },
    {
      label: "explicit override",
      personaId: "persona-anyone",
      personas: [
        {
          id: "persona-anyone",
          respondTo: "anyone",
          respondToAllowlist: [],
        },
      ],
      request: { respondTo: "owner-only" },
      expectedMode: "owner-only",
      expectedAllowlist: [],
    },
  ];

  for (const scenario of scenarios) {
    const { personaId } = scenario;
    const existing = makeAgent(personaId);
    const calls = [];
    globalThis.window ??= {};
    window.__TAURI_INTERNALS__ = {
      invoke(command, args) {
        calls.push([command, args]);
        assert.equal(command, "update_managed_agent");
        return Promise.resolve({
          agent: toRawAgent({
            ...existing,
            respondTo: args.input.respondTo,
            respondToAllowlist: args.input.respondToAllowlist,
          }),
          profile_sync_error: null,
        });
      },
    };

    const result = await provisionChannelManagedAgent(
      {
        runtime: RUNTIME,
        name: "reviewer",
        personaId,
        ...scenario.request,
      },
      {
        managedAgents: [existing],
        channelMemberPubkeys: new Set(),
        personas: scenario.personas,
      },
    );

    assert.equal(calls.length, 1, scenario.label);
    assert.equal(
      calls[0][1].input.respondTo,
      scenario.expectedMode,
      scenario.label,
    );
    assert.deepEqual(
      calls[0][1].input.respondToAllowlist,
      scenario.expectedAllowlist,
      scenario.label,
    );
    assert.equal(result.agent.respondTo, scenario.expectedMode, scenario.label);
    assert.deepEqual(
      result.agent.respondToAllowlist,
      scenario.expectedAllowlist,
      scenario.label,
    );
  }
});

test("reuse skips updates when the owner-only default already matches", async (t) => {
  const priorWindow = globalThis.window;
  t.after(() => {
    globalThis.window = priorWindow;
  });

  globalThis.window ??= {};
  window.__TAURI_INTERNALS__ = {
    invoke(command) {
      assert.fail(`unexpected ${command} call`);
    },
  };

  for (const personaId of ["persona-1", null]) {
    const existing = makeAgent(personaId, {
      respondTo: "owner-only",
      respondToAllowlist: [],
    });
    const result = await provisionChannelManagedAgent(
      {
        runtime: RUNTIME,
        name: "reviewer",
        personaId,
      },
      {
        managedAgents: [existing],
        channelMemberPubkeys: new Set(),
        personas: [],
      },
    );

    assert.equal(result.agent, existing);
  }
});

test("composer identity reuse applies policy before attaching", async (t) => {
  const priorWindow = globalThis.window;
  t.after(() => {
    globalThis.window = priorWindow;
  });

  const scenarios = [
    {
      label: "generic default",
      personaId: null,
      personas: [],
      expectedMode: "owner-only",
      expectedAllowlist: [],
    },
    {
      label: "persona unset default",
      personaId: "persona-owner",
      personas: [
        {
          id: "persona-owner",
          respondTo: null,
          respondToAllowlist: [],
        },
      ],
      expectedMode: "owner-only",
      expectedAllowlist: [],
    },
    {
      label: "persona anyone default",
      personaId: "persona-anyone",
      personas: [
        {
          id: "persona-anyone",
          respondTo: "anyone",
          respondToAllowlist: [ALLOWED_PUBKEY],
        },
      ],
      expectedMode: "anyone",
      expectedAllowlist: [ALLOWED_PUBKEY],
    },
    {
      label: "persona allowlist default",
      personaId: "persona-allowlist",
      personas: [
        {
          id: "persona-allowlist",
          respondTo: "allowlist",
          respondToAllowlist: [ALLOWED_PUBKEY],
        },
      ],
      expectedMode: "allowlist",
      expectedAllowlist: [ALLOWED_PUBKEY],
    },
  ];

  for (const scenario of scenarios) {
    const existing = makeAgent(scenario.personaId);
    const sequence = [];
    globalThis.window ??= {};
    window.__TAURI_INTERNALS__ = {
      invoke(command, args) {
        assert.equal(command, "update_managed_agent", scenario.label);
        sequence.push("update");
        return Promise.resolve({
          agent: toRawAgent({
            ...existing,
            respondTo: args.input.respondTo,
            respondToAllowlist: args.input.respondToAllowlist,
          }),
          profile_sync_error: null,
        });
      },
    };

    const result = await prepareManagedAgentMentionsForChannel({
      mentionPubkeys: [existing.pubkey],
      channelId: "channel-1",
      managedAgents: [existing],
      personas: scenario.personas,
      attachAgent: async ({ agent }) => {
        sequence.push("attach");
        assert.equal(agent.respondTo, scenario.expectedMode, scenario.label);
        assert.deepEqual(
          agent.respondToAllowlist,
          scenario.expectedAllowlist,
          scenario.label,
        );
      },
      startAgent: async () => {
        assert.fail(`unexpected start for ${scenario.label}`);
      },
    });

    assert.deepEqual(sequence, ["update", "attach"], scenario.label);
    assert.deepEqual(result, { errors: [], pubkeys: [PUBKEY] }, scenario.label);
  }
});

test("composer identity reuse does not attach when the policy update fails", async (t) => {
  const priorWindow = globalThis.window;
  t.after(() => {
    globalThis.window = priorWindow;
  });

  const existing = makeAgent("persona-owner");
  globalThis.window ??= {};
  window.__TAURI_INTERNALS__ = {
    invoke(command) {
      assert.equal(command, "update_managed_agent");
      return Promise.reject(new Error("policy update failed"));
    },
  };

  const result = await prepareManagedAgentMentionsForChannel({
    mentionPubkeys: [existing.pubkey],
    channelId: "channel-1",
    managedAgents: [existing],
    personas: [
      {
        id: "persona-owner",
        respondTo: null,
        respondToAllowlist: [],
      },
    ],
    attachAgent: async () => {
      assert.fail("agent attached after its policy update failed");
    },
    startAgent: async () => {
      assert.fail("agent started after its policy update failed");
    },
  });

  assert.deepEqual(result.pubkeys, []);
  assert.deepEqual(result.errors, ["reviewer: policy update failed"]);
});

test("composer identity reuse applies policy before starting a newly added participant", async (t) => {
  const priorWindow = globalThis.window;
  t.after(() => {
    globalThis.window = priorWindow;
  });

  const existing = makeAgent("persona-owner", { status: "stopped" });
  const sequence = [];
  globalThis.window ??= {};
  window.__TAURI_INTERNALS__ = {
    invoke(command, args) {
      assert.equal(command, "update_managed_agent");
      sequence.push("update");
      return Promise.resolve({
        agent: toRawAgent({
          ...existing,
          respondTo: args.input.respondTo,
          respondToAllowlist: args.input.respondToAllowlist,
        }),
        profile_sync_error: null,
      });
    },
  };

  const result = await prepareManagedAgentMentionsForChannel({
    mentionPubkeys: [existing.pubkey],
    channelId: "channel-1",
    managedAgents: [existing],
    personas: [
      {
        id: "persona-owner",
        respondTo: null,
        respondToAllowlist: [],
      },
    ],
    participantPubkeys: [existing.pubkey],
    newlyAddedParticipantPubkeys: [existing.pubkey],
    attachAgent: async () => {
      assert.fail("unexpected attach for an existing participant");
    },
    startAgent: async () => {
      sequence.push("start");
    },
  });

  assert.deepEqual(sequence, ["update", "start"]);
  assert.deepEqual(result, { errors: [], pubkeys: [PUBKEY] });
});
