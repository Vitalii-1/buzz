import type { Channel } from "@/shared/api/types";

export type NavigationHistoryEntry = {
  index: number;
  key: string;
  label: string;
};

const MAX_HISTORY_MENU_ENTRIES = 10;

export function getBackHistoryEntries(
  entriesByIndex: ReadonlyMap<number, NavigationHistoryEntry>,
  currentIndex: number,
): NavigationHistoryEntry[] {
  const entries: NavigationHistoryEntry[] = [];

  for (
    let index = currentIndex - 1;
    index >= 0 && entries.length < MAX_HISTORY_MENU_ENTRIES;
    index -= 1
  ) {
    const entry = entriesByIndex.get(index);
    if (entry) {
      entries.push(entry);
    }
  }

  return entries;
}

export function getForwardHistoryEntries(
  entriesByIndex: ReadonlyMap<number, NavigationHistoryEntry>,
  currentIndex: number,
  maxIndex: number,
): NavigationHistoryEntry[] {
  const entries: NavigationHistoryEntry[] = [];

  for (
    let index = currentIndex + 1;
    index <= maxIndex && entries.length < MAX_HISTORY_MENU_ENTRIES;
    index += 1
  ) {
    const entry = entriesByIndex.get(index);
    if (entry) {
      entries.push(entry);
    }
  }

  return entries;
}

type HistoryLocation = {
  pathname: string;
  search: unknown;
};

function searchHasValue(search: unknown, key: string): boolean {
  if (typeof search !== "object" || search === null) {
    return false;
  }

  const value = (search as Record<string, unknown>)[key];
  return typeof value === "string" && value.length > 0;
}

export function describeHistoryLocation(
  location: HistoryLocation,
  channels: readonly Channel[],
): string {
  const { pathname, search } = location;

  if (pathname.startsWith("/channels/")) {
    const [, , encodedChannelId, childRoute] = pathname.split("/");
    const channelId = encodedChannelId
      ? decodeURIComponent(encodedChannelId)
      : "";
    const channel = channels.find((candidate) => candidate.id === channelId);
    const channelLabel = channel
      ? channel.channelType === "dm"
        ? channel.name
        : `#${channel.name}`
      : "Channel";

    if (
      childRoute === "posts" ||
      searchHasValue(search, "thread") ||
      searchHasValue(search, "messageId")
    ) {
      return `${channelLabel} thread`;
    }

    return channelLabel;
  }

  if (pathname === "/messages/new") return "New message";
  if (pathname === "/agents") return "Agents";
  if (pathname === "/workflows") return "Workflows";
  if (pathname.startsWith("/workflows/")) return "Workflow details";
  if (pathname === "/projects") return "Projects";
  if (pathname.startsWith("/projects/")) return "Project details";
  if (pathname === "/pulse") return "Pulse";
  if (pathname === "/reminders") return "Reminders";
  if (pathname === "/settings") return "Settings";

  return "Inbox";
}
