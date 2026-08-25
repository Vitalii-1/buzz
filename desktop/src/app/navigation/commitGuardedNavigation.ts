import {
  allowNavigation,
  type GuardedNavigation,
} from "@/app/navigation/navigationGuard";
import { beginChannelSwitchTrace } from "@/shared/lib/channelSwitchPerf";

/**
 * commitGuardedNavigation runs the shared commit flow for app navigations:
 * skip same-destination no-ops (unless forced), consult the navigation
 * guard, then navigate. When `traceChannelId` is set, the channel-switch
 * trace opens only after the guard accepts — a refused click must not leave
 * an orphan trace that a later history navigation (deliberately untraced)
 * would settle with the refused click's inflated wall time. Returns whether
 * the navigation was performed. `deps` exists for unit tests.
 */
export async function commitGuardedNavigation(
  input: {
    currentHref: string;
    nextHref: string;
    force?: boolean;
    guardedTarget: GuardedNavigation;
    traceChannelId?: string;
    navigate: () => Promise<unknown>;
  },
  deps: {
    allow?: typeof allowNavigation;
    beginTrace?: typeof beginChannelSwitchTrace;
  } = {},
): Promise<boolean> {
  const allow = deps.allow ?? allowNavigation;
  const beginTrace = deps.beginTrace ?? beginChannelSwitchTrace;
  if (input.currentHref === input.nextHref && !input.force) {
    return false;
  }
  if (!allow(input.guardedTarget)) {
    return false;
  }
  if (input.traceChannelId !== undefined) {
    beginTrace(input.traceChannelId);
  }
  await input.navigate();
  return true;
}
