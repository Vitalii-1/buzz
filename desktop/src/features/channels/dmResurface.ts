import type {
  FeedItem,
  HomeFeedResponse,
  RelayEvent,
} from "@/shared/api/types";
import { CHANNEL_MESSAGE_EVENT_KINDS } from "@/shared/constants/kinds";
import { normalizePubkey } from "@/shared/lib/pubkey";

const CHANNEL_MESSAGE_KINDS = new Set<number>(CHANNEL_MESSAGE_EVENT_KINDS);
const HEX_PUBKEY = /^[0-9a-f]{64}$/;

export function dmPeerPubkeysFromFeedItem(
  item: FeedItem,
  currentPubkey: string | undefined,
): string[] {
  const self = normalizePubkey(currentPubkey ?? "");
  const candidates = [
    item.pubkey,
    ...item.tags
      .filter((tag) => tag[0] === "p" && typeof tag[1] === "string")
      .map((tag) => tag[1]),
  ];

  return [...new Set(candidates.map(normalizePubkey))].filter(
    (pubkey) => HEX_PUBKEY.test(pubkey) && pubkey !== self,
  );
}

export function dmPeerPubkeysFromRelayEvent(
  event: RelayEvent,
  currentPubkey: string | undefined,
): string[] {
  return dmPeerPubkeysFromFeedItem(
    {
      id: event.id,
      kind: event.kind,
      pubkey: event.pubkey,
      content: event.content,
      createdAt: event.created_at,
      channelId:
        event.tags.find((tag) => tag[0] === "h" && tag[1])?.[1] ?? null,
      channelName: "",
      tags: event.tags,
      category: "mention",
    },
    currentPubkey,
  );
}

export function isIncomingDmMessageFeedItem(
  item: FeedItem,
  currentPubkey: string | undefined,
): boolean {
  const self = normalizePubkey(currentPubkey ?? "");
  if (
    !item.channelId ||
    self.length === 0 ||
    !CHANNEL_MESSAGE_KINDS.has(item.kind) ||
    normalizePubkey(item.pubkey) === self
  ) {
    return false;
  }

  return item.tags.some(
    (tag) => tag[0] === "p" && normalizePubkey(tag[1] ?? "") === self,
  );
}

export function isIncomingDmMessageRelayEvent(
  event: RelayEvent,
  currentPubkey: string | undefined,
): boolean {
  return isIncomingDmMessageFeedItem(
    {
      id: event.id,
      kind: event.kind,
      pubkey: event.pubkey,
      content: event.content,
      createdAt: event.created_at,
      channelId:
        event.tags.find((tag) => tag[0] === "h" && tag[1])?.[1] ?? null,
      channelName: "",
      tags: event.tags,
      category: "mention",
    },
    currentPubkey,
  );
}

export function markHiddenDmFeedItems(
  feed: HomeFeedResponse,
  hiddenDmIds: ReadonlySet<string>,
): HomeFeedResponse {
  if (hiddenDmIds.size === 0) return feed;

  const mark = (item: FeedItem): FeedItem =>
    item.channelId && hiddenDmIds.has(item.channelId)
      ? { ...item, channelType: "dm" }
      : item;

  return {
    ...feed,
    feed: {
      mentions: feed.feed.mentions.map(mark),
      needsAction: feed.feed.needsAction.map(mark),
      activity: feed.feed.activity.map(mark),
      agentActivity: feed.feed.agentActivity.map(mark),
    },
  };
}
