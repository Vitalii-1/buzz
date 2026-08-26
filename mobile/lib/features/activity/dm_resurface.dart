import 'feed_item.dart';
import '../../shared/relay/relay.dart';

final _hexPubkey = RegExp(r'^[0-9a-f]{64}$');

Set<String> _peerPubkeys({
  required String authorPubkey,
  required List<List<String>> tags,
  required String currentPubkey,
}) {
  final self = currentPubkey.trim().toLowerCase();
  final candidates = <String>{authorPubkey.trim().toLowerCase()};
  for (final tag in tags) {
    if (tag.length >= 2 && tag[0] == 'p') {
      candidates.add(tag[1].trim().toLowerCase());
    }
  }
  candidates.removeWhere(
    (pubkey) => pubkey == self || !_hexPubkey.hasMatch(pubkey),
  );
  return candidates;
}

Set<String> dmPeerPubkeysFromFeedItem(FeedItem item, String currentPubkey) =>
    _peerPubkeys(
      authorPubkey: item.pubkey,
      tags: item.tags,
      currentPubkey: currentPubkey,
    );

Set<String> dmPeerPubkeysFromEvent(NostrEvent event, String currentPubkey) =>
    _peerPubkeys(
      authorPubkey: event.pubkey,
      tags: event.tags,
      currentPubkey: currentPubkey,
    );

bool isIncomingDmMessageEvent(NostrEvent event, String currentPubkey) {
  final self = currentPubkey.trim().toLowerCase();
  return event.channelId != null &&
      EventKind.channelMessageEventKinds.contains(event.kind) &&
      event.pubkey.toLowerCase() != self &&
      event.tags.any(
        (tag) =>
            tag.length >= 2 && tag[0] == 'p' && tag[1].toLowerCase() == self,
      );
}
