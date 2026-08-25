import assert from "node:assert/strict";
import test from "node:test";

import {
  demoBuildConfig,
  productionBuildIdentity,
} from "./demo-build-config.mjs";

const expected = (name, slug) => ({
  name,
  slug,
  productName: `Buzz ${name}`,
  dmgVolumeName: `Buzz ${name}`,
  dmgFileStem: `Buzz_${name.replace(/ /g, "_")}`,
  identifier: `xyz.block.buzz.app.demo.${slug}`,
  appDataIdentity: `xyz.block.buzz.app.demo.${slug}`,
  deepLinkScheme: `buzz-demo-${slug}`,
  keyringService: `buzz-desktop-demo.${slug}`,
  nestName: `.buzz-demo-${slug}`,
  cliName: `buzz-demo-${slug}`,
  tauriConfig: {
    productName: `Buzz ${name}`,
    identifier: `xyz.block.buzz.app.demo.${slug}`,
    plugins: { "deep-link": { desktop: { schemes: [`buzz-demo-${slug}`] } } },
    bundle: { targets: ["app"] },
  },
});

test("production identity remains unchanged", () => {
  assert.deepEqual(productionBuildIdentity, {
    productName: "Buzz",
    identifier: "xyz.block.buzz.app",
    deepLinkScheme: "buzz",
    keyringService: "buzz-desktop",
    nestName: ".buzz",
    cliName: "buzz",
  });
});

test("two demo names produce complete, distinct identities", () => {
  const board = demoBuildConfig("Workstream Board");
  const interests = demoBuildConfig("Interests Demo");
  assert.deepEqual(board, expected("Workstream Board", "workstream-board"));
  assert.deepEqual(interests, expected("Interests Demo", "interests-demo"));
  for (const key of [
    "productName",
    "dmgVolumeName",
    "dmgFileStem",
    "identifier",
    "appDataIdentity",
    "deepLinkScheme",
    "keyringService",
    "nestName",
    "cliName",
  ]) {
    assert.notEqual(board[key], interests[key], key);
    assert.notEqual(board[key], productionBuildIdentity[key], key);
  }
});

test("whitespace normalization preserves deterministic identity", () => {
  assert.deepEqual(
    demoBuildConfig("  Workstream   Board  "),
    demoBuildConfig("Workstream Board"),
  );
});

for (const name of [
  "",
  "   ",
  "Workstream/Board",
  "Workstream_Board",
  "équipe",
  "x".repeat(49),
]) {
  test(`rejects unusable name ${JSON.stringify(name)}`, () =>
    assert.throws(() => demoBuildConfig(name)));
}
