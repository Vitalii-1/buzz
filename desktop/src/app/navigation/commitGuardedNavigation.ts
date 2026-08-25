import {
  allowNavigation,
  type GuardedNavigation,
} from "@/app/navigation/navigationGuard";
import {
  beginChannelSwitchTrace,
  dropActiveChannelSwitchTrace,
} from "@/shared/lib/channelSwitchPerf";

/**
 * commitGuardedNavigation runs the shared commit flow for app navigations:
 * skip same-destination no-ops (unless forced), consult the navigation
 * guard, then navigate. When `traceChannelId` is set, the channel-switch
 * trace opens only after the guard accepts — a refused click must not leave
 * an orphan trace that a later history navigation (deliberately untraced)
 * would settle with the refused click's inflated wall time. When
 * `leavesChannelSurface` is set, any active trace is dropped instead: the
 * trace may be live with no channel screen mounted (route still resolving),
 * so this is the only reliable exit hook. Returns whether the navigation was
 * performed. `deps` exists for unit tests.
 */
export async function commitGuardedNavigation(
  input: {
    currentHref: string;
    nextHref: string;
    force?: boolean;
    guardedTarget: GuardedNavigation;
    leavesChannelSurface?: boolean;
    traceChannelId?: string;
    navigate: () => Promise<unknown>;
  },
  deps: {
    allow?: typeof allowNavigation;
    beginTrace?: typeof beginChannelSwitchTrace;
    dropActiveTrace?: typeof dropActiveChannelSwitchTrace;
  } = {},
): Promise<boolean> {
  const allow = deps.allow ?? allowNavigation;
  const beginTrace = deps.beginTrace ?? beginChannelSwitchTrace;
  const dropActiveTrace = deps.dropActiveTrace ?? dropActiveChannelSwitchTrace;
  if (input.currentHref === input.nextHref && !input.force) {
    return false;
  }
  if (!allow(input.guardedTarget)) {
    return false;
  }
  if (input.leavesChannelSurface) {
    dropActiveTrace();
  }
  if (input.traceChannelId !== undefined) {
    beginTrace(input.traceChannelId);
  }
  await input.navigate();
  return true;
}
