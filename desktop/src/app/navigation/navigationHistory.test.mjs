import assert from "node:assert/strict";
import test from "node:test";

import {
  describeHistoryLocation,
  getBackHistoryEntries,
  getForwardHistoryEntries,
} from "./navigationHistory.ts";

function entry(index) {
  return { index, key: `key-${index}`, label: `Entry ${index}` };
}

test("back history returns the nearest ten entries in reverse order", () => {
  const entriesByIndex = new Map(
    Array.from({ length: 13 }, (_, index) => [index, entry(index)]),
  );

  assert.deepEqual(
    getBackHistoryEntries(entriesByIndex, 13).map(({ index }) => index),
    [12, 11, 10, 9, 8, 7, 6, 5, 4, 3],
  );
});

test("forward history returns the nearest ten entries in navigation order", () => {
  const entriesByIndex = new Map(
    Array.from({ length: 14 }, (_, index) => [index, entry(index)]),
  );

  assert.deepEqual(
    getForwardHistoryEntries(entriesByIndex, 0, 13).map(({ index }) => index),
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
  );
});

test("history labels identify channel and thread destinations", () => {
  const channels = [
    {
      id: "channel-a",
      name: "general",
      channelType: "stream",
    },
    {
      id: "dm-a",
      name: "Ada Lovelace",
      channelType: "dm",
    },
  ];

  assert.equal(
    describeHistoryLocation(
      { pathname: "/channels/channel-a", search: {} },
      channels,
    ),
    "#general",
  );
  assert.equal(
    describeHistoryLocation(
      {
        pathname: "/channels/channel-a",
        search: { thread: "message-a" },
      },
      channels,
    ),
    "#general thread",
  );
  assert.equal(
    describeHistoryLocation(
      { pathname: "/channels/dm-a", search: {} },
      channels,
    ),
    "Ada Lovelace",
  );
});

test("history labels cover static and detail routes", () => {
  assert.equal(
    describeHistoryLocation({ pathname: "/", search: {} }, []),
    "Inbox",
  );
  assert.equal(
    describeHistoryLocation({ pathname: "/projects", search: {} }, []),
    "Projects",
  );
  assert.equal(
    describeHistoryLocation(
      { pathname: "/projects/project-a", search: {} },
      [],
    ),
    "Project details",
  );
});
