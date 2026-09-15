# Personal root network repair

This branch builds **v2rayNG Personal**, an independently installed app. Its root networking changes were developed on a rooted Xiaomi 13 running Android 16. The original app can coexist, but only one root tunnel owner may run at a time.

## Behavior

Root startup now owns core startup, firewall acquisition, the physical-network DNS lease, and teardown in a serialized service lifetime. Startup reports success after routing and DNS are ready. Duplicate starts do not create additional tunnels; stopping cancels pending work and removes capture before stopping the core. Background restarts rebuild within the existing foreground service.

Firewall operations use bounded lock waits and table batches. A preflight rejects occupied tunnel, routing-table, priority, or chain names. Teardown removes owned state and restores saved kernel settings instead of flushing priority ranges. Root command output is bounded and cannot defer the execution deadline indefinitely.

Root DNS has a dedicated TCP/UDP inbound whose port comes from the existing local DNS setting. Root mode enables the SOCKS UDP support required by its tunnel. The DNS compiler preserves ordered domain-only routing rules and ordered resolver fallbacks. Rules constrained by process, port, network, protocol, or IP do not become unconditional DNS policies; traffic-block rules do not become DNS host overrides. Private domains use the physical network's DNS when available.

The DNS helper journals the original physical-network resolver configuration before changing it and verifies the result. It restores only a configuration that is still owned by that lease. Network IDs, interfaces, transport types, the app UID, and resolver addresses are discovered at runtime. Other Android network IDs, including IMS networks, retain their DNS paths. The helper's stdin lifetime also triggers cleanup if the app daemon dies; it is not a periodic firewall writer.

When root IPv6 is disabled, captured ordinary apps receive empty AAAA results and immediate IPv6 rejection. Infrastructure UIDs, protected sockets, local destinations, and tailnet traffic retain bypasses.

A narrowly matched compatibility rule lets a system-owned Linux `tailscaled` resume Android routing when its outer sockets would otherwise hit its own unreachable rule. It derives priorities and daemon UID from system state, checks for an existing main-table default, and declines unknown layouts or collisions. The compatibility rules are journaled and removed on root teardown. Starting `tailscaled` after v2rayNG may require restarting root mode. This does not repair the standalone Linux daemon's routing while v2rayNG is stopped.

## Build and identity

Initialize submodules recursively and build the AAR and HEV inputs using `.github/workflows/build.yml`. Generated libraries, signing keys, subscriptions, and device settings are not source inputs in this branch.

`APPLICATION_ID_OVERRIDE` and `VERSION_NAME_SUFFIX` in `V2rayNG/gradle.properties` control the personal identity. The Gradle script falls back to the original application ID when no override is provided. Sign updates with the same personal key; another signature cannot replace an installed personal release.

From `V2rayNG/`:

```sh
./gradlew :app:testPlaystoreDebugUnitTest :app:compilePlaystoreDebugKotlin \
  :app:assemblePlaystoreDebug :app:lintPlaystoreDebug :app:assemblePlaystoreRelease
```

## Validation record

Production source revision: `c3d8af1c`. Tested native inputs match the repository's AndroidLibXrayLite gitlink (Xray v26.9.9). Test data and screenshots remain outside the public repository.

- 104 JVM tests passed; Kotlin compilation, debug assembly, lint, and release assembly passed. Existing lint warnings remain. Release APK inspection found both HEV libraries and `libgojni.so` for each of the four declared ABIs.
- Android 16 / arm64, personal signed release: 20 root start/stop cycles; duplicate start; repeated stop; short and expired xtables contention; foreign-chain rejection; stop during setup; restart; stop racing restart; daemon crash cleanup. The final cycle checks include creation and removal of both tailnet compatibility rules.
- Final release: 100 cold/warm DNS queries across UDP/TCP and A/AAAA passed. Warm median latency was approximately 0.9–1.25 ms; the slowest cold query took 913 ms. AAAA success means an intentional empty NOERROR response under the selected IPv4 policy.
- Final release: Wi-Fi to mobile and back; DNS and HTTPS after handover; stop racing handover; deliberately invalid configuration during handover; cleanup and recovery. One earlier in-flight UDP query was lost during the actual native reload; settled-path tests wait for the handover debounce.
- Before the isolated tailnet route changes, ten Taobao home and ten flash-sale page captures showed product photos and prices. These are visual checks, not measured page-completion timings. Transparent HTTP checks under an ordinary app UID reached Taobao and Google successfully.
- Final release: two tailnet peers responded after the application installed its compatibility rules.
- Before the isolated tailnet route changes, VPN and proxy-only modes passed cold/duplicate starts, foreground restart, network handover, stop racing handover, normal/repeated stop, and invalid-DNS setup failure. These results do not cover every shared-lifecycle race.

The one-hour observation and final device handover are recorded separately after completion.

## Limits and checks not run

Managed root DNS currently requires Android 10 or newer, Private DNS off, a recognized version of the stable DNS resolver interface, and an available installed resolver Parcelable. Unsupported layouts fail explicitly. Runtime verification covers this Android 16 device; it does not establish broad OEM compatibility.

If every resolver in a matching DNS group is unreachable, the current Xray DNS outbound can drop the failed response rather than return SERVFAIL. With both domestic resolvers blocked, the UDP test reached its six-second deadline; resolution recovered after removing the block. Primary-only failure switched to the configured backup after about two seconds. The native core was not patched for the all-upstream failure case. See [the pinned DNS outbound implementation](https://github.com/XTLS/Xray-core/blob/v26.9.9/proxy/dns/dns.go).

**Not run:** VPN/proxy-only stop during native setup and stop racing a pending restart with a deterministic scheduling barrier. Those existing synchronous setup/restart paths have no device-test barrier; the successful scenarios above do not establish these races. The broader shared lifecycle change is therefore not presented as fully runtime-verified or submitted upstream with this repair.

**Not run:** physical-device coverage for other Android versions/ABIs, IPv6-enabled root routing, or LAN/hotspot sharing. The available device was arm64/Android 16, and its selected root policy disables IPv6 capture and LAN sharing. Packaging checks cover the other declared ABIs, not their runtime behavior.

**Not run:** an actual reboot, IMS voice/SMS activity, or controlled push-delivery timing unless a separate device observation records it. Resolver readback preserved the IMS network configurations; that is not an end-to-end call/SMS test.

The generic bounded command runner is isolated in [upstream PR #6234](https://github.com/2dust/v2rayNG/pull/6234). The personal DNS/lifecycle/OEM policy is maintained in this branch.
