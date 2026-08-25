import assert from "node:assert/strict";
import test from "node:test";

import { provisionChannelManagedAgent } from "./channelAgents.ts";

const PUBKEY = "a".repeat(64);
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

test("reuse applies the owner-only default and clears stale allowlists", async (t) => {
  const priorWindow = globalThis.window;
  t.after(() => {
    globalThis.window = priorWindow;
  });

  for (const personaId of ["persona-1", null]) {
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
      },
      {
        managedAgents: [existing],
        channelMemberPubkeys: new Set(),
      },
    );

    assert.equal(calls.length, 1);
    assert.equal(calls[0][1].input.respondTo, "owner-only");
    assert.deepEqual(calls[0][1].input.respondToAllowlist, []);
    assert.equal(result.agent.respondTo, "owner-only");
    assert.deepEqual(result.agent.respondToAllowlist, []);
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
      },
    );

    assert.equal(result.agent, existing);
  }
});
