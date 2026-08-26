import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_hooks/flutter_hooks.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';

import '../community/community.dart';
import '../community/community_provider.dart';
import '../relay/relay_provider.dart';
import '../relay/relay_session.dart';
import '../relay/signed_event_relay.dart';
import 'dev_push_lease.dart';
import 'push_bridge.dart';
import 'push_relay_capability_provider.dart';
import 'push_subscription.dart';

const _pushBootstrapRetryDelay = Duration(seconds: 5);

@visibleForTesting
class BuzzPushAttemptGate {
  BuzzPushAttemptGate({this.retryDelay = _pushBootstrapRetryDelay});

  final Duration retryDelay;
  String? _attempt;
  Timer? _retryTimer;

  bool tryBegin(String attempt) {
    if (_attempt == attempt) return false;
    _retryTimer?.cancel();
    _retryTimer = null;
    _attempt = attempt;
    return true;
  }

  void failed(String attempt, {required VoidCallback retry}) {
    if (_attempt != attempt) return;
    _attempt = null;
    _retryTimer?.cancel();
    _retryTimer = Timer(retryDelay, () {
      _retryTimer = null;
      if (_attempt == null) retry();
    });
  }

  void dispose() => _retryTimer?.cancel();
}

@visibleForTesting
String buzzPushPublicationAttemptKey({
  required String communityId,
  required String relayBaseUrl,
  required String token,
  required BuzzPushLeaseDescriptor descriptor,
  required List<BuzzPushSubscription> subscriptions,
}) => [
  communityId,
  relayBaseUrl,
  token,
  descriptor.executorKeyId,
  descriptor.executorPubkey,
  buzzPushSubscriptionsFingerprint(subscriptions),
].join('|');

/// Starts the push lifecycle only after authenticated relay connectivity and a
/// push-capable NIP-11 descriptor are both present.
class BuzzPushBootstrap extends HookConsumerWidget {
  const BuzzPushBootstrap({required this.child, super.key});

  final Widget child;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    useListenable(apnsDeviceToken);
    final registrationAttempt = useMemoized(BuzzPushAttemptGate.new);
    final publicationAttempt = useMemoized(BuzzPushAttemptGate.new);
    final registrationRetry = useState(0);
    final publicationRetry = useState(0);
    final session = ref.watch(relaySessionProvider);
    final config = ref.watch(relayConfigProvider);
    final community = ref.watch(activeCommunityProvider).value;
    final memberPubkey = ref.watch(myPubkeyProvider);
    final descriptor = ref.watch(currentRelayPushDescriptorProvider).value;

    useEffect(
      () => () {
        registrationAttempt.dispose();
        publicationAttempt.dispose();
      },
      const [],
    );

    useEffect(
      () {
        if (!_ready(session, config, community, memberPubkey) ||
            descriptor == null) {
          return null;
        }
        final attempt = '${community!.id}|${config.baseUrl}';
        if (!registrationAttempt.tryBegin(attempt)) return null;
        unawaited(() async {
          try {
            await startBuzzPushRegistrationIfCapable(
              descriptor,
              startRegistration: startBuzzPushRegistration,
            );
          } catch (error, stack) {
            registrationAttempt.failed(
              attempt,
              retry: () {
                if (context.mounted) registrationRetry.value += 1;
              },
            );
            debugPrint('Push registration bootstrap failed: $error');
            debugPrintStack(stackTrace: stack);
          }
        }());
        return null;
      },
      [
        session.status,
        config.baseUrl,
        community?.id,
        memberPubkey,
        descriptor,
        registrationRetry.value,
      ],
    );

    final token = apnsDeviceToken.value;
    useEffect(
      () {
        if (!_ready(session, config, community, memberPubkey) ||
            descriptor == null ||
            token == null) {
          return null;
        }
        final state = community!.pushSubscriptionState;
        if (state.desired.isEmpty) return null;
        final attempt = buzzPushPublicationAttemptKey(
          communityId: community.id,
          relayBaseUrl: config.baseUrl,
          token: token,
          descriptor: descriptor,
          subscriptions: state.desired,
        );
        if (!publicationAttempt.tryBegin(attempt)) return null;
        final relay = SignedEventRelay(
          session: ref.read(relaySessionProvider.notifier),
          nsec: config.nsec!,
        );
        unawaited(
          _publish(ref, config, community, memberPubkey!, relay).catchError((
            Object error,
            StackTrace stack,
          ) {
            publicationAttempt.failed(
              attempt,
              retry: () {
                if (context.mounted) publicationRetry.value += 1;
              },
            );
            debugPrint('Push lease bootstrap failed: $error');
            debugPrintStack(stackTrace: stack);
          }),
        );
        return null;
      },
      [
        session.status,
        config.baseUrl,
        community?.id,
        community?.pushSubscriptionState,
        memberPubkey,
        descriptor,
        token,
        publicationRetry.value,
      ],
    );

    return child;
  }

  static bool _ready(
    SessionState session,
    RelayConfig config,
    Community? community,
    String? memberPubkey,
  ) =>
      session.status == SessionStatus.connected &&
      community != null &&
      config.nsec != null &&
      config.nsec!.isNotEmpty &&
      memberPubkey != null &&
      memberPubkey.isNotEmpty;

  static Future<void> _publish(
    WidgetRef ref,
    RelayConfig config,
    Community community,
    String memberPubkey,
    SignedEventRelay relay,
  ) async {
    final state = community.pushSubscriptionState;
    final desired = state.desired;
    final descriptor = await fetchBuzzPushLeaseDescriptor(config.baseUrl);
    final grant = await enrollBuzzPush(
      config.wsUrl,
      Env.pushGatewayUrl,
      communitiesForSnapshotRefresh:
          ref.read(communityListProvider).value ?? [community],
    );
    // Relay lease replacement and gateway delegation are independent state
    // machines. Subscription changes advance only the kind-30350 generation;
    // the opaque grant remains reusable until its own authority changes.
    final leaseGeneration = (state.acceptedGeneration ?? 0) + 1;

    await publishBuzzDevPushLeaseThroughRelay(
      grant: grant,
      leaseGeneration: leaseGeneration,
      descriptor: descriptor,
      nsec: config.nsec!,
      memberPubkey: memberPubkey,
      subscriptions: desired,
      relay: relay,
    );
    await ref
        .read(communityListProvider.notifier)
        .markPushLeaseAccepted(
          community.id,
          subscriptions: desired,
          generation: leaseGeneration,
        );
  }
}
