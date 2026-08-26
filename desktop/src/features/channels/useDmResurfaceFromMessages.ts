import * as React from "react";

import { relayClient } from "@/shared/api/relayClient";
import type { RelayEvent } from "@/shared/api/types";
import { CHANNEL_MESSAGE_EVENT_KINDS } from "@/shared/constants/kinds";
import {
  dmPeerPubkeysFromRelayEvent,
  isIncomingDmMessageRelayEvent,
} from "./dmResurface";
import { fetchHiddenDmIds } from "./useHiddenDmIds";

type UseDmResurfaceFromMessagesOptions = {
  pubkey: string | undefined;
  reopen: (pubkeys: string[]) => Promise<unknown>;
};

export function useDmResurfaceFromMessages({
  pubkey,
  reopen,
}: UseDmResurfaceFromMessagesOptions) {
  const handledEventIdsRef = React.useRef(new Set<string>());
  const pendingChannelIdsRef = React.useRef(new Set<string>());
  const reopenLatest = React.useEffectEvent(reopen);
  const handleEvent = React.useEffectEvent(async (event: RelayEvent) => {
    if (!pubkey || !isIncomingDmMessageRelayEvent(event, pubkey)) return;
    if (!handledEventIdsRef.current.add(event.id)) return;

    const channelId =
      event.tags.find((tag) => tag[0] === "h" && tag[1])?.[1] ?? null;
    if (!channelId || pendingChannelIdsRef.current.has(channelId)) return;

    try {
      const hiddenDmIds = await fetchHiddenDmIds(pubkey);
      if (!hiddenDmIds.has(channelId)) return;
      const peers = dmPeerPubkeysFromRelayEvent(event, pubkey);
      if (peers.length === 0) return;

      if (pendingChannelIdsRef.current.has(channelId)) return;
      pendingChannelIdsRef.current.add(channelId);
      try {
        await reopenLatest(peers);
      } finally {
        pendingChannelIdsRef.current.delete(channelId);
      }
    } catch (error) {
      handledEventIdsRef.current.delete(event.id);
      console.error("Failed to resurface hidden DM", channelId, error);
    }
  });

  React.useEffect(() => {
    const normalizedPubkey = pubkey?.trim().toLowerCase() ?? "";
    handledEventIdsRef.current.clear();
    pendingChannelIdsRef.current.clear();
    if (!normalizedPubkey) return;

    let disposed = false;
    let unsubscribe: (() => Promise<void>) | undefined;
    void relayClient
      .subscribeLive(
        {
          kinds: [...CHANNEL_MESSAGE_EVENT_KINDS],
          "#p": [normalizedPubkey],
          since: Math.floor(Date.now() / 1_000),
          limit: 100,
        },
        (event) => void handleEvent(event),
      )
      .then((dispose) => {
        if (disposed) {
          void dispose().catch(() => {});
          return;
        }
        unsubscribe = dispose;
      })
      .catch((error) => {
        if (!disposed) {
          console.error("Failed to subscribe to hidden DM activity", error);
        }
      });

    return () => {
      disposed = true;
      void unsubscribe?.().catch(() => {});
    };
  }, [pubkey]);
}
