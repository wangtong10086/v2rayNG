# Personal root network repair

This branch builds **v2rayNG Personal**, an independently installed app. Its root networking changes were developed on a rooted Xiaomi 13 running Android 16. The two application IDs can be installed together, but they share the default local proxy port and root resource names. Running the original root implementation can fail on the occupied port and its unconditional teardown can remove the personal app's capture chains. Use one active installation. On the test device, the original app was backed up and uninstalled at the owner's request after this conflict was reproduced.

## Behavior

Root startup now owns core startup, firewall acquisition, the physical-network DNS lease, and teardown in a serialized service lifetime. Startup reports success after routing and DNS are ready. Duplicate starts do not create additional tunnels; stopping cancels pending work and removes capture before stopping the core. Background restarts rebuild within the existing foreground service.

Firewall operations use bounded lock waits and table batches. A preflight rejects occupied tunnel, routing-table, priority, or chain names. Teardown removes owned state and restores saved kernel settings instead of flushing priority ranges. Root command output is bounded and cannot defer the execution deadline indefinitely.

Root DNS has a dedicated TCP/UDP inbound whose port comes from the existing local DNS setting. Root mode enables the SOCKS UDP support required by its tunnel. The DNS compiler preserves ordered domain-only routing rules and ordered resolver fallbacks. Rules constrained by process, port, network, protocol, or IP do not become unconditional DNS policies; traffic-block rules do not become DNS host overrides. Private domains use the physical network's DNS when available.

The DNS helper journals the original physical-network resolver configuration before changing it and verifies the result. It restores only a configuration that is still owned by that lease. Network IDs, interfaces, transport types, the app UID, and resolver addresses are discovered at runtime. Other Android network IDs, including IMS networks, retain their DNS paths. The helper's stdin lifetime also triggers cleanup if the app daemon dies; it is not a periodic firewall writer.

When root IPv6 is disabled, captured ordinary apps receive empty AAAA results and immediate IPv6 rejection. Infrastructure UIDs, protected sockets, local destinations, and tailnet traffic retain bypasses.

A narrowly matched compatibility rule lets a system-owned Linux `tailscaled` resume Android routing when its outer sockets would otherwise hit its own unreachable rule. It derives priorities and daemon UID from system state, checks for an existing main-table default, and declines unknown layouts or collisions. The compatibility rules are journaled and removed on root teardown. Starting `tailscaled` after v2rayNG may require restarting root mode. This does not repair the standalone Linux daemon's routing while v2rayNG is stopped.

## Application bypass in root mode

A root service acquisition now resolves the configured package list afresh and retains one application-policy snapshot for IPv4 capture, IPv6 capture/rejection, and DNS refreshes. Reinstalling an application cannot reuse a stale cached UID on the next connection. Network changes reuse the active snapshot; changing application selection takes effect through a service restart. Existing preference names and their include/exclude semantics remain compatible. The DNS adjustment applies to root mode; VPN and proxy-only implementations are unchanged.

For excluded applications, an owner-UID return precedes DNS DNAT as well as data capture and IPv6 rejection. Android netd queries are shared system traffic and cannot be attributed to their requesting application by a socket-owner match. These retain ordered domain-based DNS selection. An application bypass therefore does not promise a separate system resolver for each application, and shared UIDs cannot have different bypass policies.

The device configuration is separate from this generic implementation. In the reported WeChat/Idlefish case, per-app selection was disabled while three WeChat business domains had explicit proxy rules ahead of China-direct rules. A final unmatched UDP/443 block also covered otherwise unclassified services. The repair replaced the unused historical app selection with the two requested direct applications, removed the WeChat proxy/block pair and the catch-all UDP/443 block, and placed the installed Tencent/Alibaba service groups ahead of proxy groups. Domain-only direct groups use domestic DNS; explicit overseas services retain remote DNS and proxy routing. Neither application names nor device UID values are embedded in production source.

A same-Wi-Fi comparison reproduced a failed 3.6 MB file transfer under the original configuration. With only per-application data bypass enabled in the old APK, and DNS/domain rules unchanged, the user reported the same file completed in about two seconds. After installing Personal.2 and applying the complete configuration, the user confirmed three successful file uploads and a normal Idlefish IP-region display. This isolates the root interception path as sufficient to trigger the observed transfer regression; it does not distinguish a HEV transport issue from a particular original core routing decision. The experiment does not establish that DNS alone caused that upload failure.

The Personal.2 build passes 114 JVM tests, Kotlin compilation, and Play Store debug/release assembly for the deployed arm64 ABI. The update retains the previous signing certificate and all seven native library hashes. Runtime checks passed for two stop/start cycles, duplicate starts, occupied-chain acquisition failure cleanup, stop during setup, restart, Wi-Fi/cellular handover, and stop racing handover. Both application exemptions remained ahead of IPv4 marking, IPv6 rejection, and DNS DNAT after each reconciliation. Twenty-four app-UID DNS queries, 36 handover queries, eight primary-resolver-failure queries, and four recovery queries passed; Google HTTPS returned 204 on Wi-Fi, cellular, and restored Wi-Fi. Primary-resolver fault injection was removed and original radio settings were restored.

UID-scoped probes using the same runtime-resolved HTTPS destination observed the same China egress for the physical network, WeChat, and Idlefish, and a different US egress for foreground Chrome. The initial background Chrome probe was invalid for routing comparison because Android reported effective APP_BACKGROUND blocking; bringing it to the foreground removed that restriction without changing system policy. These are UID-routing probes, not captures of the applications’ internal region requests. Native IPv6 TCP connected for the two bypass UIDs, while captured foreground Chrome received a rejection in approximately 0.6 ms under the configured IPv4-only proxy policy. No literal service IP was added to production routing.

A five-minute locked, USB-connected observation passed 48 additional DNS queries with unchanged daemon/tunnel identities. This was ordinary screen-off testing, not forced deep Doze. Temporary firewall fault rules and diagnostic files were removed, original radio settings restored, and root mode left running. Auditing the earlier repair found the 619 expected module payloads and 2,146 denylist entries unchanged; the approved Thanox delegate setting remained disabled.

The user subsequently confirmed that the requested fresh WeChat notification appeared within five seconds while the phone remained locked. Together with the three confirmed file transfers and corrected Idlefish region display, this completes the reported application-level acceptance checks. Notification timing is user-reported; no exact sender timestamp or event-to-notification interval was established for this trial.

**Not run:** separate image/video-send acceptance.

## Build and identity

Initialize submodules recursively and build the AAR and HEV inputs using `.github/workflows/build.yml`. Generated libraries, signing keys, subscriptions, and device settings are not source inputs in this branch.

`APPLICATION_ID_OVERRIDE` and `VERSION_NAME_SUFFIX` in `V2rayNG/gradle.properties` control the personal identity. The Gradle script falls back to the original application ID when no override is provided. Sign updates with the same personal key; another signature cannot replace an installed personal release.

From `V2rayNG/`:

```sh
./gradlew :app:testPlaystoreDebugUnitTest :app:compilePlaystoreDebugKotlin \
  :app:assemblePlaystoreDebug :app:lintPlaystoreDebug :app:assemblePlaystoreRelease
```

## Validation record

Initial validation source revision: `c3d8af1c`. The later IPv6 repair and its checks are recorded separately below. Tested native inputs match the repository's AndroidLibXrayLite gitlink (Xray v26.9.9). Test data and screenshots remain outside the public repository.

- 104 JVM tests passed; Kotlin compilation, debug assembly, lint, and release assembly passed. Existing lint warnings remain. Release APK inspection found both HEV libraries and `libgojni.so` for each of the four declared ABIs.
- Android 16 / arm64, personal signed release: 20 root start/stop cycles; duplicate start; repeated stop; short and expired xtables contention; foreign-chain rejection; stop during setup; restart; stop racing restart; daemon crash cleanup. The final cycle checks include creation and removal of both tailnet compatibility rules.
- Final release: 100 cold/warm DNS queries across UDP/TCP and A/AAAA passed. Warm median latency was approximately 0.9–1.25 ms; the slowest cold query took 913 ms. AAAA success means an intentional empty NOERROR response under the selected IPv4 policy.
- Final release: Wi-Fi to mobile and back; DNS and HTTPS after handover; stop racing handover; deliberately invalid configuration during handover; cleanup and recovery. One earlier in-flight UDP query was lost during the actual native reload; settled-path tests wait for the handover debounce.
- Final release: ten Taobao home and ten flash-sale page captures were individually inspected; all showed product photos, prices, and content. Each iteration restarted the app without clearing its data or cache. These are visual checks, not measured page-completion timings.
- Final release: transparent HTTP checks under the foreground Taobao UID reached the LAN gateway, Taobao, and Google. The same UID reached two tailnet peers after the application installed its compatibility rules. Earlier synthetic probes under that UID were denied while Android reported an effective `APP_BACKGROUND` restriction; the foreground retest passed without changing that policy.
- During the screen-off observation, the user confirmed that a real new WeChat message produced a timely notification. Delivery latency was not measured with a stopwatch.
- Before the isolated tailnet route changes, VPN and proxy-only modes passed cold/duplicate starts, foreground restart, network handover, stop racing handover, normal/repeated stop, and invalid-DNS setup failure. These results do not cover every shared-lifecycle race.

During continued use after the passing captures, the user reported another prolonged gray placeholder when entering the flash-sale page, followed by gradual content loading. The app was foreground and unrestricted, and the root/DNS probes still passed. Subsequent refresh captures reproduced the symptom with root enabled, with root stopped on Wi-Fi, and with root stopped on mobile data after restarting Taobao. In the mobile baseline, the page remained a gray skeleton at 20 seconds and displayed its network-error view at 45 seconds. Root capture rules, the tunnel, and the managed DNS lease were absent in the stopped baselines. These results do not establish that the intermittent symptom is fixed or that root mode is its sole cause.

Application logs repeatedly recorded two requests for the same homepage API. One completed successfully in less than a second; the other had a start record without a completion record in the capture window. A fallback homepage request started approximately 20 seconds later. Completed-request statistics therefore miss part of the observed delay. At that stage, the outstanding application request did not distinguish a client defect from a server or other device-side cause.

Two reversible experiments did not provide a lasting fix: rebuilding only Taobao's offline resource cache, and temporarily rejecting its UDP/443 traffic to exercise HTTP/2/HTTPS. Each initially produced a successful refresh, then reproduced the delay during further testing. The original resource cache was restored and the temporary rejection rule was removed. The installed Taobao version matched the version offered by the device's application store; no application update was installed. No application-specific UID or server address was added to the production networking code.

The continuous root/DNS observation completed in 3,602 seconds with 61 passing samples and 26 minutes of continuous screen-off time. It included Wi-Fi/mobile handover. The daemon and tunnel process identities remained stable throughout that observation; final observation logs contained no matched root/DNS failures or fatal exception, and tunnel error/drop counters were zero. These infrastructure checks did not detect the concurrent Taobao UI symptom. The personal quick-settings tile also stopped and restarted the root service, with owned-state cleanup and recreation verified. At that point no permanent storage workaround had been applied. The subsequent component comparison and final configuration below resolved the observed mount defect without removing denylist records.

## Subsequent Flash page causal investigation

On the same device, Taobao and several other Magisk-denylisted applications shared a mount namespace without the system `/storage` mount. Taobao's video-cache code repeatedly attempted to create a file under its external cache directory. File operations returned ENOENT, followed by EROFS when directory creation reached the read-only ancestor. Thread stacks and a bounded syscall trace placed two occupied callback workers in `libtaobaoplayer.so`, reached through `CacheConnection.notifyResponse`.

Read-only inspection of the installed application showed that Repeater dispatch assigns each request sequence to one of eight single-thread executor queues using its Java string hash. In the failing refresh, both homepage requests finished at the network layer in approximately 0.8 and 1.1 seconds, but one request's response, data and finish callbacks waited behind a video-cache task. The application started a fallback request after approximately 20 seconds. Inspection found 370 tasks pending across the two occupied queues.

A temporary bind of the existing system storage into the affected namespace, with root HEV, DNS and routing held constant, emptied those queues and released an old homepage completion approximately 710 seconds after its network finish. Three subsequent refreshes completed normally. The intervention affected every application sharing that namespace and survived Taobao process restarts; it was not confined to one application process. A later device reboot removed it. No persistent mount script was installed.

With explicit authorization for testing only, the package's 41 main-package and corresponding isolated-process denylist records were temporarily removed. The remaining 2,105 records and all module files were retained. After a cold launch, Taobao entered a separate namespace with normal system storage. Restoring the original complete list and relaunching returned it to the shared namespace. This was repeated after the reboot had removed the temporary bind: storage was absent with the original list, present with the package records removed, and absent again after restoration. Other observed denylisted applications retained their missing-storage state throughout this package-scoped experiment. Full-list comparisons verified rollback, including on interrupted UI-test paths.

After that clean reboot, two cold Flash entries, 20 warm entries and ten refreshes produced 32 valid page samples. Each three-second-target screenshot was individually inspected and showed store/product content and images. The warm samples span two temporary candidate launches; an interrupted sixth entry in the first launch is excluded. Before the clean reboot, one additional cold entry and three refreshes also showed content. Twenty DNS queries passed during a candidate run, and eight more passed after final rollback. The original 2,146 denylist records were restored, Taobao again had missing storage, and the phone's temporary diagnostic directory was removed. These results validate the candidate under the sampled conditions without deploying it permanently.

The observed failure chain therefore runs from the denylist-dependent mount environment, through failing video-cache file operations and occupied callback queues, to delayed delivery of already-completed network requests. It does not support adding Taobao-specific DNS, UID, server-IP or mount-repair code to v2rayNG. At this earlier stage, the component interaction creating the incorrect shared namespace was still unisolated. The installed Zygisk Next uses its unmount-only mode; a trace of NoHello's companion did not show it unmounting `/storage`. NoHello's documentation asks users to disable Zygisk Next's Enforce DenyList setting, which provides a compatibility investigation lead, not proof of sole responsibility. See [NoHello's usage instructions](https://github.com/MhmRdd/NoHello#usage).

A Java method-replacement probe crashed Taobao; that sample was discarded and the probe was removed. Later observation used library logging controls, read-only reflection, thread stacks and bounded syscall traces. Cold process restarts removed process-local observation settings, and the instrumentation server was removed. UI samples interrupted by a system weather crash dialog or departure from the Flash page are excluded from successful page counts. Screenshot deadlines are not exact page-completion timings and cannot establish a page-latency p95.

The reboot also exercised the documented tailnet startup-order limitation: the core, root tunnel and managed DNS were running, but the two compatibility bridges were absent until a reconnect. A diagnostic Boolean that required those bridges was false; that was not evidence that the native core was stopped.

## Final storage configuration and component comparison

A controlled comparison isolated the Zygisk Next / NoHello interaction. With Zygisk Next unmount-only processing and NoHello both enabled, Android first completed the application-specific storage mounts, then a late namespace switch moved the application into the storage-less namespace daemon. NoHello's pre-specialization hook suppressed forwarding the original mount-namespace unshare. The late switch was attributed to Zygisk Next. With either component's mount processing used alone, storage was present; restoring the original combination reproduced the late switch after the successful mounts. This is evidence of an ordering interaction, not an observed `/storage` unmount by NoHello.

The deployed configuration disables Zygisk Next's Enforce DenyList processing and retains the original NoHello module. All 2,146 original denylist records, including the 41 Taobao records, remain intact. The original NoHello mount rules were extended by one source-root rule:

```text
root { "*/adb/modules/*" }
```

This was necessary because disabling Zygisk Next alone left direct module-file bind mounts visible. The installed-version parser and mount-root resolver were used offline against the captured mount tables: the extra rule matched module-backed files without matching storage, user data, or core-directory mounts. Two boots of the complete configuration retained storage and application data mounts for Taobao, WeChat, Chrome and Google services, with no captured module-path mount markers. No kernel, SELinux, app-data or module-binary change was needed. A 619-file audit matched the expected configuration; there was no unaccounted module-file difference.

Final storage validation included three cold Flash entries, 20 warm entries and ten valid refreshes, with every three-second-target image inspected. Actual application cache writes and sync calls were observed from outside the process. A trace with unpaired boundary/lost events cannot establish that no file error ever occurred. A later in-process Java probe crashed Taobao and timed out for WeChat; that entire acceptance attempt was discarded, and no further process injection was used. Screen captures obscured by promotion dialogs were also excluded and repeated. The final post-configuration network and screen-off checks passed 84 DNS queries, but root DNS success was not treated as proof of application notification delivery.

## IPv6 rejection reply repair

Production source revision `887678a9` fixes a separate root networking defect. When IPv6 capture is disabled, a kernel-generated rejection response traverses OUTPUT again. It has no original app socket owner and its destination can be the phone's own global IPv6 address. The old rejection chain rejected that reply too, leaving the app waiting for a timeout. Simply changing the rejection type to TCP reset was insufficient.

The disabled-IPv6 path now allows loopback output before app capture and uses TCP reset for TCP, retaining ICMP rejection for other protocols. UID selection, protected/system sockets, local bypasses, IPv4 and enabled-IPv6 marking retain their existing behavior. No application package, device UID or server address was added to production rules.

A same-UID intervention and reverse test changed repeated three-second IPv6 TCP timeouts to sub-millisecond failures only when the reply path and TCP reset were both present. Six probes after installing the same-certificate release failed in 0.610–0.809 ms; root IPv6 transport and the application UID's IPv4 transport remained usable. All 108 JVM tests passed, including reply ordering, selected-UID scope, bypass precedence and unchanged IPv4/enabled-IPv6 behavior. Kotlin compilation and debug/release assembly passed. The arm64 release retained all seven original native libraries byte-for-byte. This patch did not upgrade native dependencies.

The installed release additionally passed 36 DNS queries, three HTTPS 204 checks and Wi-Fi/mobile/Wi-Fi handover, restoring the prior radio settings. A further Taobao cold-entry image at about 3.43 seconds showed store/product content.

## WeChat notification coverage and remaining limits

Real-message tests exposed another device policy interaction. Thanox's automatic reclaim rule terminates background WeChat processes 30 seconds after an FCM event, and an existing root script consumes the same reclaim record. Separately, Android recorded push-process termination after repeated Binder-freezing failures. Temporarily disabling the 30-second rule did not eliminate the notification failure.

The decisive reminder gap involved Thanox's option to skip delegated notifications whenever WeChat was already running. A new FCM event reached the phone while WeChat processes existed, but neither a new delegated notification nor a native notification was captured during the failure interval. Temporarily disabling only the skip option, with the same processes retained and the other trial conditions unchanged, produced a delegated notification 25 ms after the next FCM event; a native notification followed at 564 ms. The user confirmed seeing a notification within five seconds. After both temporary changes were restored, the owner explicitly approved permanently disabling only the skip option. All reclaim-rule definitions and other Thanox setting values were retained.

Delegated notifications are published under Android's system package on Thanox's dedicated WeChat channel. An earlier analysis omitted that channel and incorrectly treated a native notification about 58 seconds later as the first user-visible reminder. Reviewing the complete event record corrected that claim: the earlier delegated reminder had been published within 49 ms. Counting only the WeChat application package is not a valid reminder-delivery check.

The skip-option change provides delegated reminders while app processes exist; it can also produce a delegated reminder followed by the app's own reminder. It does not establish why every native message synchronization stalled or prevent Android's Binder/freezer termination. The original FCM health script also used an obsolete fixed Google-services process suffix and reported missing connections despite a live GcmService socket; that independent monitoring defect was identified but not changed.

## Duplicate installation startup failure

The failing Start button belonged to the original application ID while the personal daemon was already listening on the configured SOCKS port. The original daemon logged `bind: address already in use`. Its saved root teardown script unconditionally deleted the same capture chains used by the personal app. This explains why leaving both copies available was unsafe: a failed attempt by the old implementation could disrupt the running repair even though its own core never started.

The original APK and MMKV data were backed up locally. The owner requested uninstalling the original copy, leaving the personal app as the only active installation. After removal, two actual UI stop/start cycles passed. Each stop removed the owned root resources; the following button starts reached routing/DNS readiness in 1.361 and 1.376 seconds. Twenty DNS queries and a proxied HTTPS 204 check then passed. The personal app remained connected, with one owned tunnel, one copy of each root jump, the DNS lease and both tailnet compatibility rules present. Private keys, node definitions, APK backups, phone logs and screenshots are kept outside Git.

## Limits and checks not run

Managed root DNS currently requires Android 10 or newer, Private DNS off, a recognized version of the stable DNS resolver interface, and an available installed resolver Parcelable. Unsupported layouts fail explicitly. Runtime verification covers this Android 16 device; it does not establish broad OEM compatibility.

If every resolver in a matching DNS group is unreachable, the current Xray DNS outbound can drop the failed response rather than return SERVFAIL. With both domestic resolvers blocked, the UDP test reached its six-second deadline; resolution recovered after removing the block. Primary-only failure switched to the configured backup after about two seconds. The native core was not patched for the all-upstream failure case. See [the pinned DNS outbound implementation](https://github.com/XTLS/Xray-core/blob/v26.9.9/proxy/dns/dns.go).

**Not run:** VPN/proxy-only stop during native setup and stop racing a pending restart with a deterministic scheduling barrier. Those existing synchronous setup/restart paths have no device-test barrier; the successful scenarios above do not establish these races. The broader shared lifecycle change is therefore not presented as fully runtime-verified or submitted upstream with this repair.

**Not run:** physical-device coverage for other Android versions/ABIs, IPv6-enabled root routing, or LAN/hotspot sharing. The available device was arm64/Android 16, and its selected root policy disables IPv6 capture and LAN sharing. Packaging checks cover the other declared ABIs, not their runtime behavior.

**Not run:** IMS voice/SMS activity, deep Doze, battery consumption, or throughput stress. Resolver readback preserved the IMS network configurations; that is not an end-to-end call/SMS test. The screen-off observation used a USB-connected, charging device and does not establish deep-idle behavior. Actual reboot observations are recorded above; they do not establish unattended recovery from every boot ordering.

**Not run:** long-term reliability across future module/app upgrades, or measured page-completion p95. Component-isolated comparisons and two boots of the complete storage configuration are recorded above. No permanent denylist-entry removal was applied.

The generic bounded command runner is isolated in [upstream PR #6234](https://github.com/2dust/v2rayNG/pull/6234). The personal DNS/lifecycle/OEM policy is maintained in this branch.
