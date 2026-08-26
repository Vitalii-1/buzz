import * as React from "react";
import {
  useCanGoBack,
  useRouter,
  useRouterState,
} from "@tanstack/react-router";
import { isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

import { matchBackForwardChord } from "@/app/navigation/backForwardChords";
import {
  type BackHistoryEntry,
  getBackHistoryEntries,
} from "@/app/navigation/navigationHistory";
import {
  traverseHistory,
  traverseHistoryBy,
} from "@/app/navigation/navigationGuard";
import { isMacPlatform } from "@/shared/lib/platform";
import { trimMapToSize } from "@/shared/lib/trimMapToSize";

type RouterHistoryState = {
  __TSR_index?: number;
  __TSR_key?: string;
  key?: string;
};

const MAX_TRACKED_HISTORY_ENTRIES = 200;

export function useBackForwardControls(currentLabel: string) {
  const router = useRouter();
  const canGoBack = useCanGoBack();
  const locationState = useRouterState({
    select: (state) => state.location.state,
  }) as RouterHistoryState;
  const locationIndex = locationState.__TSR_index ?? 0;
  const locationKey =
    locationState.__TSR_key ?? locationState.key ?? String(locationIndex);
  const [historyState, setHistoryState] = React.useState(() => ({
    entriesByIndex: new Map<number, BackHistoryEntry>([
      [
        locationIndex,
        { index: locationIndex, key: locationKey, label: currentLabel },
      ],
    ]),
    maxIndex: locationIndex,
  }));

  React.useEffect(() => {
    setHistoryState((current) => {
      const entriesByIndex = new Map(current.entriesByIndex);
      const currentEntry = entriesByIndex.get(locationIndex);
      const replacedForwardEntry =
        currentEntry !== undefined && currentEntry.key !== locationKey;

      if (replacedForwardEntry) {
        for (const storedIndex of entriesByIndex.keys()) {
          if (storedIndex >= locationIndex) {
            entriesByIndex.delete(storedIndex);
          }
        }
      }

      entriesByIndex.set(locationIndex, {
        index: locationIndex,
        key: locationKey,
        label: currentLabel,
      });
      trimMapToSize(entriesByIndex, MAX_TRACKED_HISTORY_ENTRIES);

      return {
        entriesByIndex,
        maxIndex: replacedForwardEntry
          ? locationIndex
          : Math.max(current.maxIndex, locationIndex),
      };
    });
  }, [currentLabel, locationIndex, locationKey]);

  const canGoForward = locationIndex < historyState.maxIndex;
  const backHistory = React.useMemo(
    () => getBackHistoryEntries(historyState.entriesByIndex, locationIndex),
    [historyState.entriesByIndex, locationIndex],
  );

  const goBack = React.useCallback(() => {
    if (!canGoBack) {
      return;
    }

    traverseHistory(router.history, "back");
  }, [canGoBack, router.history]);

  const goForward = React.useCallback(() => {
    if (!canGoForward) {
      return;
    }

    traverseHistory(router.history, "forward");
  }, [canGoForward, router.history]);

  const goBackTo = React.useCallback(
    (index: number) => {
      const delta = index - locationIndex;
      if (delta >= 0 || !historyState.entriesByIndex.has(index)) {
        return;
      }

      traverseHistoryBy(router.history, delta);
    },
    [historyState.entriesByIndex, locationIndex, router.history],
  );

  const handleKeyDown = React.useEffectEvent((event: KeyboardEvent) => {
    // Note: the chords deliberately fire even when focus is inside an
    // editable element. The composer autofocuses on every channel switch
    // (`useComposerAutofocus`), so in steady state focus almost always
    // lives in a contenteditable — an editable-target guard here made the
    // shortcuts effectively dead (#3775). Safe because neither ⌘[ / ⌘]
    // (macOS) nor Alt+←/→ (Windows/Linux) carry text-editing semantics,
    // and the TipTap editor binds no conflicting shortcuts.
    const direction = matchBackForwardChord(event, isMacPlatform());

    if (direction === "back") {
      event.preventDefault();
      goBack();
      return;
    }

    if (direction === "forward") {
      event.preventDefault();
      goForward();
    }
  });

  const handleMouseNav = React.useEffectEvent((direction: string) => {
    if (direction === "back") {
      goBack();
      return;
    }

    if (direction === "forward") {
      goForward();
    }
  });

  React.useEffect(() => {
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, []);

  // macOS: WKWebView never delivers X1/X2 button events or horizontal
  // swipe gestures to the DOM, so the native layer catches them
  // (`mouse_nav.rs`) and forwards them as a Tauri event.
  React.useEffect(() => {
    if (!isTauri()) {
      return;
    }

    const unlistenPromise = listen<string>("mouse-nav", (event) => {
      handleMouseNav(event.payload);
    });

    return () => {
      void unlistenPromise.then((unlisten) => unlisten());
    };
  }, []);

  return {
    backHistory,
    canGoBack,
    canGoForward,
    goBack,
    goBackTo,
    goForward,
  };
}
