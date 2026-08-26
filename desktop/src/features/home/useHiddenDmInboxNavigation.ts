import * as React from "react";

import { useAppNavigation } from "@/app/navigation/useAppNavigation";
import { dmPeerPubkeysFromFeedItem } from "@/features/channels/dmResurface";
import { useOpenDmMutation } from "@/features/channels/hooks";
import type { InboxItem } from "@/features/home/lib/inbox";
import { getThreadReference } from "@/features/messages/lib/threading";

type UseHiddenDmInboxNavigationOptions = {
  availableChannelIds: ReadonlySet<string>;
  currentPubkey: string | undefined;
  onOpenContext: (
    channelId: string,
    messageId: string,
    threadRootId?: string | null,
  ) => void;
  selectedItem: InboxItem | null;
};

export function useHiddenDmInboxNavigation({
  availableChannelIds,
  currentPubkey,
  onOpenContext,
  selectedItem,
}: UseHiddenDmInboxNavigationOptions) {
  const { goChannel } = useAppNavigation();
  const openDm = useOpenDmMutation().mutateAsync;
  const openContext = React.useCallback(
    async (
      item: InboxItem,
      channelId: string,
      messageId: string,
      threadRootId?: string | null,
    ) => {
      if (
        !availableChannelIds.has(channelId) &&
        item.item.channelType === "dm"
      ) {
        const pubkeys = dmPeerPubkeysFromFeedItem(item.item, currentPubkey);
        if (pubkeys.length > 0) {
          const dm = await openDm({ pubkeys });
          onOpenContext(dm.id, messageId, threadRootId);
          return;
        }
      }
      onOpenContext(channelId, messageId, threadRootId);
    },
    [availableChannelIds, currentPubkey, onOpenContext, openDm],
  );

  return {
    canOpenSelected: Boolean(
      selectedItem?.item.channelId &&
        (availableChannelIds.has(selectedItem.item.channelId) ||
          (selectedItem.item.channelType === "dm" &&
            dmPeerPubkeysFromFeedItem(selectedItem.item, currentPubkey).length >
              0)),
    ),
    handleOpenDirect: React.useCallback(
      (item: InboxItem) => {
        const channelId = item.item.channelId;
        if (!channelId) return;
        void openContext(
          item,
          channelId,
          item.id,
          getThreadReference(item.item.tags).rootId,
        );
      },
      [openContext],
    ),
    handleOpenDm: React.useCallback(
      async (pubkeys: string[]) => {
        const dm = await openDm({ pubkeys });
        await goChannel(dm.id);
      },
      [goChannel, openDm],
    ),
    handleOpenSelectedContext: React.useCallback(
      (channelId: string, messageId: string, threadRootId?: string | null) => {
        if (selectedItem) {
          void openContext(selectedItem, channelId, messageId, threadRootId);
        }
      },
      [openContext, selectedItem],
    ),
  };
}
