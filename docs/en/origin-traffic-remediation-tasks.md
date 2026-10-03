# Origin and traffic remediation tasks

Umbrella: <https://github.com/f5-sales-demo/webapp-api-protection/issues/553>

Implementation issues: [origin-server](https://github.com/f5-sales-demo/origin-server/issues/710), [traffic-generator](https://github.com/f5-sales-demo/traffic-generator/issues/711).

Detailed operational receipts remain in the private lifecycle state directory. Baseline failures are immutable evidence and are not acceptance. Completion requires source, installed, and live checks; all incomplete tasks remain open. Preserve shared DNS, namespace identity, private state, schema fixtures and unrelated worktrees. CSD remains disabled.

## Current acceptance status

This section is authoritative for the resumed repair round. Historical sections below preserve earlier observations;
they do not establish current acceptance. All T01–T16 tasks remain incomplete.

Generator source `506d54244fc788a754486c31ba574f6ece866fa6` preserves all 164 scenarios across 22 suites.
Its required CI passed. Source checks pass 125 Python tests and nine subtests, repository-configured mypy and Pylint
across sixty Python files, and focused Node checks. No full catalog pass has yet satisfied acceptance.

Origin source `a2409bdcc4b6b77d7ada4b32fef22d61fde01306` passes 57 Python tests, type checking and
changed-file repository hooks. The DVWA redirect repair prevents already-prefixed upstream redirects from acquiring
a second prefix. Its immutable predecessor `be736289794fdc10d6a7eaf239cd37fd74d9f574` passed four rendered
checks through origin nginx and both published domains over HTTP and HTTPS. Checks covered authenticated home,
native security form submission, seeded SQL input and reflected benign input, with no browser errors or failed resources.
The twenty screenshots were manually reviewed. The native-route verifier at
`a6d95abbee77e32edfef1864efb36a1f7aef45fc` passed those same four checks on each of all four DVWA replicas.
Private receipts retain the exact source and archive digests. Full DVWA mutation fixture restoration remains open.

The current DVGA candidate derives template links from the request prefix, preserves native static asset routes,
and fixes the burn-after-read link that escaped to the shared root. Its browser verifier requires actual native paste
form submission, subscription delivery, persisted content and scoped synthetic paste removal. Immutable installation
and installed qualification are in progress; no DVGA workflow acceptance is claimed from source tests.

Continuous traffic was verified enabled and active on the generator candidate, with 9,538 of 9,538 benign requests
successful in that observed window. It was then stopped for the immutable DVGA installation. Interrupted catalog passes
remain failed evidence. Complete application workflows, fixture restoration, scanner semantics, two full passes,
merged installation, clean rebuild, final rate/control proof, reboot and zero-change repeat apply remain open.

Browser response assertions now remain mandatory even when browser actions pass. Nested reports require child source
digests matching the installed catalog. Scenario mitigation counts exclude filler, prerequisites and other scenarios.
Evicted nested evidence no longer leaves unbounded owned attribution markers. Rapid browsing declares 360 route actions
across all fifteen original user-agent identities, with components, content, controls, URL outcomes and private screenshots.
Intentional negative order, tracking, anonymous authorization and VAmPI GET routes are explicitly distinguished.

Expanded origin `671fbe167ea015363297e3ed9e068934c933cd55` passed immutable installation and required CI.
Focused BOLA qualification at generator `3edcadd371784d336645de59ed82ad222c6e94de` passed all six dispatch/response
requirements, all five synthetic profile restorations, zero transport failures and zero cancellations. Private receipt:
`resume-focused-bola-fixtures/pass-focused-1791011143124566516/receipt.json`. The prior duplicate-phone run remains
failed: its five application 500s were not accepted. Expanded probes target synthetic privileged accounts. All 33 supported
native HTTP workflows passed after the immutable reinstall. Full rendered/workflow/catalog acceptance remains open.

BOLA rerun on `ba75fb9394e34c42e416cca5e7e29390b326165d` passed without registration requests, with
all five profile restorations and zero transport failures/cancellations. Private receipt:
`resume-focused-bola-fixtures/pass-focused-1791011321925464310/receipt.json`. Self-profile source now measures CPU,
memory, disk, network, TCP states and descriptors before/during/after load. Installed `d3596fbcf6e9105dff0489db0ebd17b0d2e6bbb0`
passed 300 requests across all nine applications, actual concurrency, resource phases and minimum duration, with zero
transport failures/cancellations. Private receipt: `resume-focused-profile/pass-focused-1791011590430151567/receipt.json`.
Ephemeral workload qualification passed all 20/50/100 batches, 170 completed requests across all nine applications,
measured fresh connections and cleanup, with zero transport failures/cancellations. Private receipt:
`resume-focused-ephemeral/pass-focused-1791011683915132895/receipt.json`. This does not establish port exhaustion
or replace complete catalog and sustained-rate acceptance.

Connection comparison passed installed on `a095743c633fb132171906d93b1d84b5b0d08c8e`: 100 requests on one
reused connection and 100 on fresh connections, valid content and zero transport failures/cancellations. Private receipt:
`resume-focused-churn/pass-focused-1791011861378822523/receipt.json`. Installed `708e5bcb696f18351b0fc0ca4a89073664c98ce8`
reverified retained churn/profile/ephemeral workload evidence with the stricter all-samples gate; all passed. That
reverification qualifies the verifier against existing evidence and is not a new full catalog pass. Private receipt:
`workload-reverification-708e5bc.json`. Continuous service restart is being verified.

Nested BOLA child qualification passed through the shared pacing boundary on `fe3b7b65de395a10b400b0d1c46c4efcba0ee3df`,
with 22 attributed child requests, every declared dispatch/response requirement and profile restoration. Private receipt:
`resume-focused-nested/pass-focused-1791012333150743754/nested-restaurant-exploits/restaurant-exploits--02-bola-profile/receipt.json`.
Browser children now propagate validated opaque markers; native tool resolution skips owned wrapper chains. Aggregate
reports reject foreign receipt symlinks. Installed nested scanner/browser and complete parent stress remain open.

Installed ZAP marker qualification passed on `cc3d1a01113327aff9279491ac0fc0205f2fe75b`: the pinned native
scanner loaded its replacer configuration and dispatched the intended access request to its own child receipt through
the shared boundary. Private receipt: `resume-focused-zap-marker/pass-focused-1791012924444458872/receipt.json`.
This proves attribution only; full scanner actions/completion and Nikto attribution remain open. Earlier CI repair
revision `8838ec2` passed its Super-Linter job, but its workflow was canceled by a newer push; current required CI is pending.

Catalog reconciliation removed 699 blanket HTTP 500 allowances across 64 scenarios. All 164 entries remain.
Application crashes now fail response acceptance; intentional server-error cases require explicit case-specific evidence.
Focused historical passes retain their original sources and outcomes. Current source passes 114 tests and nine subtests;
current installed catalog restart and required CI are pending. Generator `dc8da02` completed green required CI.
Startup readiness now rejects arbitrary HTTP 405 on declared healthy pages. Full per-case status/content reconciliation remains open.

Slow-header evidence now records every write round and explicit peer/tool errors. The first diagnostic run remains
failed, with 42 successful writes and eighteen TLS EOF errors across twenty bounded connections. Private receipt:
`resume-focused-slow-evidence/pass-focused-1791013215755636419/receipt.json`. A new verifier distinguishes recorded
peer closure from timeout/tool failure without attributing a WAAP control. Installed retry passed as a bounded probe with 42 sent headers and eighteen recorded peer-closed connections,
complete three-round evidence, duration and cleanup. Private receipt:
`resume-focused-slow-evidence/pass-focused-1791013379582960007/receipt.json`. No WAAP control is attributed; the prior
failed iteration remains failed. Full connection-scenario scope reconciliation and control attribution remain open.

Positive response verification now requires declared content type and JSON identity while retaining only assertion
booleans. RESTaurant BOLA requires the actual synthetic target username and changed phone value in every positive
mutation response. Wrong-content 200 and wrong-actor regressions fail. Installed qualification passed all response identities,
22 dispatches and profile restoration with zero transport failures/cancellations. Private receipt:
`resume-focused-bola-fixtures/pass-focused-1791013673736185449/receipt.json`. All 59 Python files pass mypy and
repository-configured Pylint. Continuous startup is being verified; complete catalog/workflow acceptance remains open.

Origin rendering crawl retained 27 screenshots and 28 checks, with one Juice Shop failure: seven Socket.IO 400
responses and eight console errors. Private run `private-render-1791013788038158000` remains failed. Direct origin
clients had an empty forwarding-header affinity key and sessions moved across replicas. Source `b91654a31f5f42e9906f81bae7225c98a8785875`
adds a remote-address fallback; 43 source tests and 68 subtests pass. Its digest-checked immutable installer passed.
Focused polling continuity now passes five of five native and five of five nginx sessions; Chromium observes an actual
WebSocket frame without a socket error. Fresh origin rendering run `private-render-1791014120430315000` passed all 28 content checks across nine
applications and retained 27 screenshots. Its contact sheet was reviewed; individual rendered workflow review remains
open. The receipt correctly retains accepted=false because authenticated workflow acceptance is incomplete. Published
serving-layer acceptance and
published serving-layer acceptance remain open. The reviewed contact sheet is a preliminary visual review only.

Native crAPI authentication exposed a seeded-role mismatch: the backend returns ROLE_PREDEFINE while the frontend
user-route guard only recognized ROLE_USER and ROLE_ADMIN. Vehicle API returned its seeded object, but the dashboard
rendered no vehicle and Community/Shop returned to dashboard. The failed browser workflow remains failed evidence.
Origin `53a54904fb70291c10c1de3636353376bc6a6cc2` adds a narrow seeded-role frontend compatibility adapter and fails
if the pinned upstream guard changes. Source checks pass 44 tests and 68 subtests; immutable installation and browser
qualification are in progress. Full workflow acceptance remains open.

Seeded-role crAPI adapter installed successfully. Chromium rendered vehicle details and image, Community posts and
Shop products; native menu clicks and deep-link refresh worked. The same run remains incomplete because automatic
chatbot state requests returned 404. Provisioning incorrectly routed chatbot requests to identity and omitted the chatbot
dependency. Source now declares an immutable native chatbot image and functional uninitialized-state readiness. Origin
`18fd2a27ce87a6e934af315868f458076e881eb3` passes 45 tests and 69 subtests; installation is pending. Accumulated
synthetic community posts remain a fixture-cleanup failure. Full crAPI/browser acceptance remains open.

The pinned chatbot dependency installed and its real uninitialized-state readiness passed. Diagnostic browser views
rendered vehicle, Community and Shop with native navigation and refresh, with the previous chatbot 404 eliminated.
The reusable stricter browser verifier at origin `522d0d5` nevertheless fails on external map transport requests.
Its five application view assertions pass, but both transport-failure runs remain failures. Private receipts:
`private-crapi-verifier-1791015610823458000/receipt.json` and `private-crapi-verifier-1791015662983845000/receipt.json`.
Origin `522d0d5b12cbd33ebb4eac558ef2233e1f1f0e62` passed the immutable installer. Installed verifier digest
matches committed source in `installed-crapi-verifier-digest.json`; strict browser transport failures remain open.
Full rendered completeness remains open.
Origin source passes 45 tests and 69 subtests; generator source passes 119 tests and nine subtests.

Community data-exposure scenario now reads pinned native seeded posts without creating random duplicates. It requires
a nonempty posts response and exact content type/JSON keys at the real recent-posts endpoint. Installed qualification
passed on `e1fde3384ba1425ddc961719f982ef7cc8ea8d2c`, with actual GET/query dispatch and response assertions,
zero transport failures/cancellations. Private receipt:
`resume-focused-community-read/pass-focused-1791016048498089525/receipt.json`. Historical duplicate data remains
a cleanup failure. Generator source passes 121 tests and nine subtests and all sixty Python files pass type checking.

The stricter seeded response contract also rejects empty or malformed posts lists; every observed post must contain
nonempty ID, title and content. Installed retry passed actual dispatch and all nonempty object assertions with zero transport failures/cancellations.
Private receipt: `resume-focused-community-read/pass-focused-1791016261901811208/receipt.json`. All sixty Python
files pass mypy and repository-configured Pylint. Full catalog completion, merged
artifacts, clean rebuild, sustained-rate/control proof and repeated Terraform apply remain open.

Current installed supported HTTP workflows passed nine checks on origin nginx and on both WAAP domains over HTTP
and HTTPS, using refreshed private fixtures. These are limited supported workflow checks, not complete rendered
application acceptance. Generator `4aa6a2c` required CI is green; origin `522d0d5` required CI is green. Current
continuous service is enabled and running on the exact generator source with no failures in its early current pass.
Full two-pass catalog, rate/control attribution, authenticated rendered workflows, mutation cleanup and Terraform
convergence remain outstanding. No T01–T16 task is marked complete from these narrower receipts.

A bounded 120-second rate window on generator `4aa6a2c` observed 197.28 aggregate requests/sec, 177.65 benign
requests/sec, 100 percent completed benign success and zero benign transport failures. Private receipt:
`rate-window-receipt.json`. This is an observation before clean deployment, not final sustained-rate acceptance.
Multi-client source now retains its 100 correlated identity echoes and adds twenty clients each rotating through all
nine application content contracts (280 total requests). Source checks pass 122 tests and nine subtests; focused
installed qualification passed 280 requests: 100 identity echoes and twenty dispatches to each of nine apps,
per-client content/cleanup evidence, zero transport failures/cancellations. Private receipt:
`resume-focused-multiclient-all/pass-focused-1791016780937147850/receipt.json`. Original randomized deep paths and all workload semantics remain open.

The remaining eighteen scenario-level blanket HTTP 500 classifications were removed to keep application crashes
distinct from expected outcomes. Request contracts already reject broad 500 allowances. VAmPI mutation scope and
shared-account restoration remain open. Current generator source preserves all 164 scenarios and passes 122 tests
with nine subtests; immutable install completed and continuous readiness/start verification is pending.

Installed verifier runtime audit found that origin provisioning installs the browser scripts but does not provision
Node/Playwright. Script digest equality is verified; installed browser runtime acceptance is incomplete. The successful
origin crawl used the operator browser host and cannot substitute for a reproducible installed verifier runtime.
Pinned runtime provisioning is an explicit remaining T09/T13 gate.

Origin `a936a2d3b72c25d47ed986aeb3909d2071031422` provisions a digest-pinned Playwright 1.63.0 runtime
with a matching integrity-locked package and source-installed verifier scripts. Package audit reports zero vulnerabilities;
46 source tests and 69 subtests pass. Immutable runtime installation passed; Origin-host locked-runtime content verification passed all 28 checks across nine applications and retained 27
screenshots. Private output: `/opt/origin-server/private-browser-1791017479808857095`. Accepted remains false because
full authenticated workflow and screenshot acceptance are incomplete; Installed crAPI workflow retry remains failed with five rendered checks passing and two external-map transport
failures. Private receipt: `/opt/origin-server/private-browser-1791017603361585040/receipt.json`. Origin runtime CI
is green. This is not complete rendered workflow acceptance.
Private installer receipt: `remediation-immutable-origin-1791017354705763175/receipt.json`. The earlier 1.55.0 candidate was
replaced after its package audit identified a fixed browser-download certificate issue; it is not an accepted runtime.

Scenario and nested child receipts now carry immutable source commit and archive digest in addition to entrypoint
digest. Aggregate reports reject mismatched artifacts/revisions even when a shell entrypoint did not change.
Source regression rejects adapter revision mismatch; 123 tests and nine subtests, mypy and configured Pylint pass.
Installed nested provenance qualification passed child dispatch/restoration, matching source commit/archive
and the aggregate report. Private child receipt:
`resume-focused-nested/pass-focused-1791017796681530580/nested-restaurant-exploits/restaurant-exploits--02-bola-profile/receipt.json`. Full nested stress and all catalog semantics remain open.

Exact request/workload endpoints are reconciled into the target matrix for 125 scenarios. Validation now rejects an
exact executable target missing from its scenario matrix. Root discovery and intentional-negative probes remain separate
from hosted application identity acceptance. All 164 entries remain; source checks pass 124 tests and nine subtests,
mypy, configured Pylint and changed-file pre-commit. Installed catalog completed; continuous startup is pending.

WAAP candidate deployment inputs now pin the exact installed origin/generator commits, archive digests and both
installer digests. Its vendored manifest matches pinned origin content, including the chatbot dependency, and outputs
carry generator source provenance plus the origin Python installer digest. Credential-free WAAP checks pass 306 tests
with one existing skip. These are candidate pins; merged-source installation and ownership-checked Terraform rebuild
remain open. Current generator CI is green and its early full pass has ten verified receipts with no failures.

Origin browser runtime now performs exact ownership-checked cleanup, rejects symlink evidence destinations and retains
a separate failed runtime receipt. Controlled installed failure left zero owned verifier containers. Source provenance
records the exact immutable commit, archive and installer in origin installation and browser runtime receipts. Origin
`4a557deb9c2f953b08739f93a1c444cfec9745b9` passed immutable installation; 50 source tests and 69 subtests,
type/lint checks pass. Full rendering failures remain failures. Continuous generator restart is being verified.

Quiet-period diagnostic retry on origin `a2a3e4149cf136cea0ecd8859eaa9d2ea2d38270` remains failed. Both
external-map requests report net::ERR_FAILED in subframes, not ERR_ABORTED navigation cancellation. All five native
application view checks pass; full rendered acceptance is still false. Private receipt:
`/opt/origin-server/private-browser-1791019546050759919/receipt.json`. Immutable installer and provenance passed;
WAAP candidate pins are reconciled with this revision and credential-free tests pass.

The current interrupted full pass reached fourteen receipts, thirteen verified and one failed rapid-browser scenario.
The retained browser checkpoint had only its first identity and browser_closed=false; a source repair now closes and
persists evidence in finally on early failure. Seven focused Node tests pass. Installed rapid retry was interrupted after confirmed blank 200 pages and navigation timeouts on
`7e7ae5e43bc9eeb71c3cd118900e456fa9f449f4`; the failed pass remains failed.

Latest rapid-browser iteration `resume-focused-rapid-final/pass-focused-1791019820323884692/receipt.json` remains
failed and interrupted before all 360 actions completed. It retains blank 200 screenshots and navigation timeouts;
mitigated requests are distinct from rendered routes. The terminal scenario receipt recorded zero transport failures
and zero cancellations. Continuous startup is being verified on the immutable candidate. No failed pass was relabeled.

DVGA batch coverage now requires single systemUpdate, exact 2/5/10 expensive batches and the mixed batch.
Generic arrays cannot establish expensive-operation dispatch. Source regression rejects wrong operations and sizes;
125 tests and nine subtests, mypy/Pylint and changed-file checks pass. Installed catalog is updated; live completion
remains open because the native 20–50 second operation and batch duration exceed existing client/upstream timeouts.
The application delay was preserved. Full catalog/rebuild acceptance remains open.

Origin evidence retention now evicts only completed owned browser runs by age/size and monitors the active cap and
deadline. Source tests preserve active/unrelated paths and reject unowned eviction. Origin `83beebf` installed
successfully. Subsequent header-scope correction keeps workflow tracking headers off third-party frames; its diagnostic
run no longer reported the prior map transport errors but hit a pending-request deadline and remains failed.
Origin `8f9c5e7` passes 53 tests and 69 subtests; Immutable installation passed. The locked-runtime crAPI retry passed all five rendered view checks with zero
errors; its five screenshots were manually reviewed for vehicle image/map, Community and Shop before/after refresh.
Private receipt: `/opt/origin-server/private-browser-1791021207307010849/receipt.json`. Earlier failures remain failed.
This qualifies native login and read-only views; signup, workshop mutations, fixtures and all published browser layers
remain open. No browser failures were suppressed.

DVWA CSRF source no longer prints unconditional exploit success. Origin `0bc63fa` provisions a dedicated
synthetic tgen_csrf account and per-domain real sessions; managed traffic uses that identity for a distinct password
change and requires original-password authentication restoration evidence. Shared admin identity is preserved.
Origin source passes 54 tests and 69 subtests; generator source passes 125 tests and nine subtests. Immutable install
and focused mutation/restoration verification are running; this task remains incomplete until observed checks pass.

First dedicated DVWA seed failed because pinned native users.user_id has no default. That fixture failure remains
failed. Origin source now supplies a noncolliding native ID and tests require it. Corrected origin `acc37c3` immutable
installation is running; full CSRF qualification remains pending. The scoped mutation cannot be accepted until real
fixture authentication and restoration both pass.

Corrected dedicated CSRF fixture export passed after native user_id repair. The first focused mutation dispatched
change/restore but failed authenticated restoration; its receipt remains failed. Source now follows login redirects
and requires Logout content instead of assuming any redirect proves authentication. Fixture was regenerated before
retry; Installed focused qualification on `4aa9c10` passed distinct password mutation, changed-password authentication,
original-password restoration/authenticated content, both intended dispatches and zero transport failures/cancellations.
Private receipt: `resume-focused-csrf-scoped/pass-focused-1791022734105439066/receipt.json`. Shared admin fixture
was preserved. Earlier seed and restore failures remain failed evidence. No exploit success is printed without observed mutation
and changed-password authentication.

Scoped CSRF also restores its dedicated account on early script exit and retains failed cleanup. The final source
`506d542` is installed; Focused normal-flow repeat passed both dispatches, real mutation/authentication/restoration, and zero transport
failures/cancellations. Private receipt: `resume-focused-csrf-scoped/pass-focused-1791022987278269891/receipt.json`. Prior accepted normal-flow source remains its own receipt and does
not qualify interruption behavior. Shared admin and unrelated fixtures remain preserved.

Juice Shop native browser diagnostic passed ten assertions: translated products/images, native login, seeded basket,
about/contact/recycle/complaint/scoreboard and observed WebSocket frames, with no recorded errors. Source-controlled
verifier is now included in the locked origin runtime; Origin `bbc2520` immutable installation passed, and locked-runtime verification passed all ten checks with zero
errors. Its eight screenshots were manually reviewed for product images, labels, supporting pages and seeded basket.
Private receipt: `/opt/origin-server/private-browser-1791023435742027870/receipt.json`. Published browser layers
are now running. This does not complete checkout or all serving-layer workflows. Full application acceptance remains open.

Published Juice Shop browser runs passed ten workflow checks on HTTPS www; HTTP www and HTTP api remain failed
with Socket.IO error and incomplete product-image assertion. All other declared workflow views rendered. These HTTP
failures are not accepted. Private outputs: `private-browser-juice-1791023514147314482`,
`private-browser-juice-1791023534348957858`, and successful HTTPS `private-browser-juice-1791023551194020428`.
HTTPS api also passed all ten checks in `private-browser-juice-1791023566571231582`. Serving-layer completeness remains open.

HTTP companion listener lacked the declared WebSocket routes. An ownership-checked saved plan updated only that
listener; apply failed provider readback because route priority materialized DEFAULT from null. Failed apply receipt is
preserved. Source now emits DEFAULT explicitly. The repair saved plan had zero resource actions and applied successfully
(0 added/changed/destroyed). This is a targeted repair check, not final full Terraform convergence. Origin verifier
`d534acf` waits for terminal product images before assertion; Immutable installation passed. Both HTTP domains now passed ten rendered workflow checks with zero errors;
private outputs: `private-browser-juice-1791024250681555708` and `private-browser-juice-1791024271883735139`.
Both HTTPS domains passed earlier on the prior verifier source. Final same-source all-layer acceptance remains open.

Checkov parsing failed the existing multiline FQDN boolean validation. The expression was reformatted with the operator
on the preceding line, preserving validation semantics; intact scanner retry is running. HTTP WebSocket source repair
is verified through saved ownership-checked plan/readback and browser checks, but final full Terraform convergence
remains open. Continuous traffic is enabled and running.

Final same-source Juice Shop browser runs passed ten assertions each on both HTTP and HTTPS domains, including
product images and WebSocket frames. Private outputs: `private-browser-juice-1791024443400890439`,
`private-browser-juice-1791024464796403123`, `private-browser-juice-1791024481190821058`, and
`private-browser-juice-1791024496081781694`. Earlier HTTP image/socket failures remain failed. These workflow checks
do not complete checkout, mutation cleanup or native replica-browser acceptance.

Three focused rapid-browser iterations remain failed or interrupted. The latest retained receipt is
`resume-focused-rapid-final/pass-focused-1791009776937631086/receipt.json`. It includes two tool cancellations and failed
response/action assertions. Response evidence shows WAAP 403 on product APIs, application scripts and images while the
main document returns 200. Mitigated navigation is recorded separately from rendered content; blocked assets do not prove
complete application rendering. No focused iteration is accepted as a full browser or application pass.

Outstanding gates include fixture snapshot/restoration and distinct BOLA actors; complete original workload semantics;
nested scanner/browser attribution; all rendered authenticated workflows and serving layers; merged immutable installs;
one ownership-scoped clean rebuild; two accepted full catalog passes; sustained rate/control attribution; restart/reboot;
and unchanged Terraform apply followed by a zero-action plan. Continuous operation alone cannot satisfy those gates.

| Task | Status | Dependencies | Acceptance criteria | Issue / PR | Source revision | Verification receipt |
| --- | --- | --- | --- | --- | --- | --- |
| T01 — Record baseline | In progress | none | Capture routes, replicas, fixtures, rendered failures, catalog, deployed digests, Terraform ownership and shared identities; retain private receipt. | <https://github.com/f5-sales-demo/webapp-api-protection/issues/553>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Pending | Private remediation-baseline/receipt.json; live baseline captured, preservation reconciliation pending |
| T02 — Application manifest | Open | T01 | Exactly nine applications reconciled across declaration, docs, landing, outputs and traffic. | <https://github.com/f5-sales-demo/origin-server/issues/710>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Pending | Pending |
| T03 — Coverage matrix | In progress | T02 | Native/published routes, replicas, assertions, fixtures and scenarios; no missing/orphan entries. | <https://github.com/f5-sales-demo/traffic-generator/issues/711>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Pending | Pending |
| T04 — Unified provisioning | Open | T02 | Both roots consume one immutable origin installer including existing pinned dependencies and repairs. | <https://github.com/f5-sales-demo/origin-server/issues/710>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Pending | Pending |
| T05 — Prefix handling | Open | T04 | Assets, links, forms, API, redirects, cookies and SPA routes retain application prefixes. | <https://github.com/f5-sales-demo/origin-server/issues/710>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Pending | Pending |
| T06 — Application defects | Open | T05 | All nine applications pass specified authenticated/seeded/rendered workflows and replica checks. | <https://github.com/f5-sales-demo/origin-server/issues/710>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Pending | Pending |
| T07 — DVWA payload coverage | Open | T03,T08 | All 15 SQLi and 18 XSS payloads reach authenticated DVWA; preserve stable scenario ID mappings. | <https://github.com/f5-sales-demo/traffic-generator/issues/711>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Pending | Pending |
| T08 — Repeatable fixtures | Open | T04 | Synthetic fixture reruns produce no duplicates; scoped mutations restored; blocked setup cannot suppress launches. | <https://github.com/f5-sales-demo/origin-server/issues/710>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Pending | Pending |
| T09 — Content verifier | Open | T03 | Landing reconciliation, navigation, rendered assets/images, console/network, forms and authentication fail closed; screenshots reviewed. | <https://github.com/f5-sales-demo/origin-server/issues/710>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Pending | Pending |
| T10 — Serving layers | Open | T06,T09 | All native replicas, origin nginx, both domains HTTP/HTTPS; identity/type correct; wrong-content 200 fails. | <https://github.com/f5-sales-demo/origin-server/issues/710>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Pending | Pending |
| T11 — Scenario receipts | In progress | T03,T07 | 164 entries across 22 suites; intended method/path/payload and browser/connection action observed apart from setup/filler. | <https://github.com/f5-sales-demo/traffic-generator/issues/711>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Generator `12ccf1fd1a3fe099ef7e910a1b57cc85e399a4fd` | Source contract matrix complete; installed full-pass qualification pending |
| T12 — Outcome attribution | Open | T11 | Explicit negative cases; mitigation, rejection, fixture/tool/transport failure and timeout distinguished. | <https://github.com/f5-sales-demo/traffic-generator/issues/711>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Pending | Pending |
| T13 — Lifecycle integration | Open | T04,T08,T10,T12 | Existing lifecycle/control verbs preserved; immutable inputs/digests/URL maps recorded; startup gated on complete readiness. | <https://github.com/f5-sales-demo/webapp-api-protection/issues/553>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Pending | Pending |
| T14 — Repair loop | Open | T13 | Source checks, installed and live gates pass on committed immutable configuration; failed receipts retained. | <https://github.com/f5-sales-demo/webapp-api-protection/issues/553>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Pending | Pending |
| T15 — Clean rebuild | Open | T14 | One ownership-checked destroy/absence/preservation/recreate from committed source; no manual fixture setup. | <https://github.com/f5-sales-demo/webapp-api-protection/issues/553>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Pending | Pending |
| T16 — Final acceptance | Open | T15 | Two complete catalog passes; 200 aggregate RPS within 5%; 180 benign equally split/rotated across nine apps; >=99% success, zero transport failures; attributed controls; stop/restart/reboot; unchanged apply then zero plan; continuous service running. | <https://github.com/f5-sales-demo/webapp-api-protection/issues/553>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Pending | Pending |

## Current verification

Origin and generator changes are committed in draft PRs. Origin source checks: seven Python regressions, rendered wrong-content and broken-image regression, full pre-commit, Terraform validation, and Docker builds passed.

Generator: 42 tests plus nine subtests, Ruff and full pre-commit passed. WAAP baseline: 330 tests passed with one existing skip.

Candidate origin guest readiness passed. An origin nginx crawl passed 43 content checks across all nine applications.
Full authenticated workflow acceptance, screenshot review, every native rendered replica, both WAAP domains, full
scenario dispatch contracts, immutable merged installation, successful clean rebuild and repeat apply remain open.
Traffic was stopped during repair. No Terraform destroy has run.

Failures retained privately include the original prefix defects, HTTPBin UTF-8 build failure, RESTaurant source-path failure, rendered adapter gaps, and incompatible legacy Werkzeug middleware. Failed iterations are not acceptance.

## Repair receipts

DVWA login, security selection, seeded SQL lookup and reflected-XSS benign workflow passed through both HTTPS domains. Origin tests: 35 passed and 68 subtests passed. Generator tests: 42 passed and nine subtests passed. WAAP tests: 306 passed with one existing skip.

A fresh 46-second traffic interval measured 197.38 aggregate requests/sec, 100% benign success and zero benign transport failures. Prior 97.6% and 98.5% intervals remain failed receipts. Full catalog acceptance has not completed on this candidate.

The latest HTTPS content crawl passed all checks except two browser-cancelled default Juice Shop logo requests while the CTF logo replaced them. A source adapter is being updated to start with the configured logo. Screenshots are retained privately; complete authenticated workflow and replica acceptance remain open.

Continuous traffic is enabled and running. The scoped saved WebSocket route plan applied one load-balancer update, no create or destroy. No clean Terraform rebuild or zero-change repeat apply has run for these candidate sources.

Both public HTTPS domains passed authenticated DVWA login, security selection, seeded SQL lookup and reflected-XSS benign workflow. CSD replica state matched. A later 46-second traffic interval passed at 197.38 aggregate requests/sec with 100% benign success and no benign transport failures.

The clean-install review added explicit nginx cache creation, adapter image provenance for DVGA recovery and manifest-derived readiness. Origin has 35 passing tests and 68 passing subtests; generator has 43 passing tests and nine passing subtests. All three PRs remain drafts because required delivery and acceptance tasks remain open.

## Outstanding delivery gates

Source request contracts cover 34 of 164 scenarios, with eleven additional CSD browser contracts and seven connection
probe adapters. The remaining scenario contracts and installed verification prevent full catalog acceptance. Source CI
and rendered diagnostics do not complete T11, T15 or T16.

No clean rebuild, two accepted complete catalog passes, unchanged repeat apply, reboot recovery or merged-artifact installation has been claimed. All three implementation PRs remain drafts. Current source, candidate installation and failed iterations are retained separately in private receipts.

The current installer rerun passed every native readiness check. The remaining rendered failure was isolated to duplicate crAPI chatbot state requests; a regression now requires both source occurrences to be guarded before login. The updated build and cross-domain rendered verification are still in progress.

The last complete installer attempt failed its readiness deadline after deployment. This remains a failed installer receipt. A subsequent focused native readiness probe passed after correcting the accepted DVGA operation name; it does not convert the failed attempt into acceptance. Continuous traffic was restored and is enabled and running on the current candidate.

The latest full rendered run was blocked by WAAP 403 responses. Complete rendered, authenticated and scenario acceptance, clean rebuild, repeat apply and merged installation remain outstanding. These failures prevent completion; source tests and passing short traffic intervals are insufficient.

## Resumed verification

Native readiness passed again on every application replica. The running generator retained zero current failures and near-100% benign success at resumption.

Dispatch verification now distinguishes prerequisite requests from execution requests, retains request attribution from
enqueue time, and verifies matching method, endpoint, body class and required counts. Four API-protection scenarios have
explicit action contracts. Endpoint-denial and rate-limit targets were corrected to the configured HTTPBin paths.
Missing fixtures produce failed private receipts without terminating the rest of the catalog. An existing contract alone
cannot mark a dispatch verified, and an incomplete contract matrix cannot mark a catalog pass accepted.

Intentional negative endpoints are tested by scenarios, while startup probes declared healthy application pages. Failed browser and installer evidence from earlier iterations remains retained. Full 164-scenario reconciliation and final rebuild acceptance remain open.

Installed dispatch receipts verified all declared schema-violation, shadow-endpoint, configured endpoint-denial and
configured rate-limit actions. The first DVWA pass dispatched every payload but failed two login redirects. After
refreshing real origin-authenticated sessions, a separate pass verified all 15 SQLi and 18 reflected-XSS launches with
no transport failures. The failed pass remains failed evidence.

Eight DVGA scenario contracts were added around valid JSON GraphQL documents, batch size, operations and payload classes. Their installed dispatch verification is still pending. A GraphQL helper transport regression verifies arbitrary query quotes and variables survive JSON construction unchanged.

## Current evidence and remaining failures

The corrected nonmutating crawl produced 58 passing HTTPS content checks across both domains. Its 56 rendered
screenshots were reviewed; application identity, images, Swagger/ReDoc and navigation were visible. Screenshot review
also found DVGA's start-over link, which resets application state; it was added to the declared mutation paths and
excluded from read-only crawling. A final crawl is pending that manifest adjustment.

Installed API-protection dispatch contracts and a refreshed authenticated DVWA payload pass succeeded. All 33 preserved
DVWA payloads dispatched. The first stale-session pass remains failed. Eight DVGA action contracts are implemented, but
a focused batch/recursion pass timed out and recorded cancellations; it is failed evidence, not successful application
rejection. Cancelling tool requests now causes scenario failure.

Generator source tests currently pass 58 tests and nine subtests. Full pre-commit passes. Native application readiness passed at resumption. CI repair, remaining catalog action contracts, every required authenticated workflow, HTTP serving-layer checks, immutable merged installation, clean rebuild, restart/reboot recovery and final repeat apply remain open.

A later native DVGA batch/recursion qualification failed and left an orphan task proxy after its controller stopped. Its private receipt remains failed. Proxy recovery now records PID, process start ticks and exact source script; tests reject PID reuse and command mismatch. The exact orphan proxy was removed without signalling unrelated processes, and continuous traffic was restarted.

Current generator source validation passes 61 tests and nine subtests plus full pre-commit. Four API-protection contracts and refreshed DVWA payload contracts have installed evidence. Eight DVGA contracts are implemented but have not passed installed acceptance. Full 164-scenario contracts, application workflow completeness and final clean rebuild remain open.

Issued-authentication workflow checks passed 17 native replica checks for Juice Shop, DVWA, VAmPI, RESTaurant
customer/chef roles and crAPI vehicle/community/workshop/MailHog content. Those checks also passed through origin nginx
and both WAAP domains over HTTP and HTTPS. The reusable verifier is committed in origin-server; complete browser
interactions and fixture mutation cleanup remain separate open requirements.

The extended reusable verifier passed 33 native application checks and nine application checks at each of origin nginx,
both WAAP HTTP domains and both WAAP HTTPS domains. HTTPBin's positive POST body was corrected to the deployed demo_id
schema; malformed bodies remain attack scenarios. These checks prove the implemented authentication and seeded content
assertions, while full browser interaction coverage and fixture cleanup remain outstanding.

The corrected nonmutating HTTPS crawl passed 56 content checks after excluding the DVGA start-over reset link. Earlier
passing-looking crawls that visited reset links are retained as diagnostic evidence, not nonmutating acceptance. Source
dispatch contracts currently cover 14 of 164 scenarios; seven connection scenarios have separate probe receipts. The
remaining action contracts prevent full catalog acceptance.

The all-nine application workflow verifier passed 33 native checks, plus nine checks at origin nginx and each WAAP
HTTP/HTTPS endpoint. crAPI source dispatch contracts now cover its 15 scenarios; installed crAPI action qualification
remains pending. Current source action contracts cover 29 of 164 scenarios, with seven additional connection probe
scenarios. Complete action coverage and final rebuild acceptance remain open.

A focused immutable crAPI qualification passed five action contracts: 20 unauthenticated mechanic-report probes, mechanic listing, three NoSQL coupon operators, 21 unauthenticated order probes and seven forged-dashboard requests. No transport failures or tool cancellations were recorded. The other ten crAPI scenario contracts still require installed qualification.

Browser/CSD contracts now require the exact manifest step assertions and successful browser cleanup, independent of network request counts. CSD remains display-only and disabled for enforcement. Source execution contracts cover 34 scenarios, plus eleven CSD browser action contracts and seven connection probes; the remaining catalog reconciliation is open.

## Current browser and connection qualification

Generator revision `db23bf793a3f20999a3ce38ca21818b53d1a8c8a` passes 67 tests and nine subtests, targeted mypy,
Pylint and pre-commit. Browser receipts now require captured screenshots with passed assertion status, exact action
steps and successful browser cleanup. A request contract cannot be overridden by a browser receipt; interrupted receipt
files fail closed. Connection verification requires the complete TLS offering matrix and certificate validation, or the
bounded slow-header writes, duration and connection cleanup for the declared probe.

The first installed eleven-scenario CSD qualification at revision `b36e7878f35f112ce783c309aa1dbbbb5df0737e` failed.
Its screenshot adapter expected the wrong receipt field. The adapter is corrected in the later source revision, and the
original receipt remains failed. Seven scenarios also recorded client cancellations, including product assets and
Socket.IO polling; those require separate remediation. CSD enforcement remains disabled and the browser suite makes
no detection claim. Corrected installed qualification is in progress; final acceptance remains open.

## Latest installed qualification

Source request contracts cover 36 scenarios; eleven CSD browser contracts and seven bounded connection adapters are
additional. The catalog remains 164 scenarios across 22 suites. Generator Python validation passes 68 tests and nine
subtests, Ruff, mypy and Pylint; full pre-commit passes. Required CI Ruff formatting/import/constant defects were repaired
in `b0587019a8b9bd76f6365260d37d6274a7923258`; current CI remains pending.

VAmPI authentication qualification passed all sixteen declared requirements, and mass assignment passed all eight
payload contracts at installed revision `f6b3a932653ec6026e4c7b306344a02a57a04b3e`, with no transport failures or
cancellations. These establish launch evidence, while fixture cleanup and complete application acceptance remain open.

CSD qualification at `2b3af044cde787195db0cc2a24a36453f5b50f63` passed ten scenarios but failed high-volume navigation:
HTTP 200 did not produce the expected login controls. The 56 screenshots were reviewed privately; its high-volume
screenshots were blank. Earlier failed adapter and cancellation runs remain failed. Declared browser cleanup now
separately counts only established Socket.IO polling sessions closed after the cleanup marker; assets and execution
cancellations still fail. CSD remains display-only with enforcement disabled. Full rendered acceptance remains open.

The installed bounded connection qualification passed six adapters: three port/protocol probes and three TLS matrices,
including certificate validation and cleanup. Slow-header qualification failed because fewer than sixty header writes
completed across twenty connections. Its receipt remains failed; the cause and expected peer-close behavior require
reconciliation before acceptance.

Native browser credential stuffing submitted all fifteen DVWA credential pairs, but failed overall on one cancellation.
Registration/contact submitted neither required action in its first corrected run; the native form response wait timed
out. Source now uses paired response/click waits, dismisses the deployed welcome controls and parses the synthetic
arithmetic captcha without evaluating JavaScript. Installed retry is in progress. Direct request fallbacks are removed.

## Current source and serving state

Latest generator candidate is `394c7f9fbdc7b81eed470459c5c639122fc5e433`. Its source checks pass 68 Python tests,
nine subtests, 24 browser unit tests, Ruff format/check, mypy, Pylint and full pre-commit. The AWS-only headed-browser
unit test is excluded outside its declared AWS runtime; this does not count as live application acceptance. CI is pending.

The latest native form retry still failed registration: both required registration requests were absent, while both
contact submissions completed with HTTP 201. A cancellation also failed the scenario. Native controls are now used for
question selection and submission, and the failure remains open. The prior disabled-control and pointer-interception
receipts remain failures. Continuous traffic was restored after focused qualification and verified enabled and running on the immutable candidate.
No merged-artifact acceptance, clean Terraform rebuild, complete catalog pass or repeat apply has been performed.

The restored service reported revision `394c7f9fbdc7b81eed470459c5c639122fc5e433`, enabled and running, with
2,769 of 2,769 benign requests successful in its initial status sample. This is liveness evidence, not sustained-rate or
full-catalog acceptance.

## Full source contract matrix

Generator revision `12ccf1fd1a3fe099ef7e910a1b57cc85e399a4fd` declares execution evidence for every one of the
164 scenarios across 22 suites: 144 request contracts, eleven CSD browser contracts, seven connection adapters and two
aggregate report contracts. Catalog validation rejects missing contracts. Source tests pass 78 tests and nine subtests;
Ruff, mypy, Pylint and full pre-commit pass. This completes source declaration only; T11 remains in progress until
installed actions, prerequisites, output semantics and complete catalog passes qualify.

Native browser registration/contact now each dispatch twice through actual UI controls with zero transport failures or
cancellations after closing the security-question menu and draining pending requests. The first fresh requests returned
201; repeat registration of existing synthetic accounts returned 400 while both contact actions returned 201. Those
responses remain distinct application outcomes, and repeatable account cleanup remains open.

Installed exact contracts passed VAmPI OWASP (22 requirements), Juice Shop SQL login (five payloads twice), SQL search
(nineteen queries), NoSQL (twenty-one payloads), and RESTaurant mass assignment (six requirements). RESTaurant command
injection first failed raw ampersand transport; source now URL-encodes the complete parameter, and a separate run passed
all nine payloads. DVWA SQL first failed quoting before dispatch; argument-based encoding repaired the source and a
separate pass dispatched all six SQL requirements. Web SSRF passed all fifteen exact payloads after header/body argv
repair. Prior failed runs remain failed evidence.

Real origin-issued DVWA sessions now feed all fourteen installed DVWA scenarios. Focused dispatch passed command
injection, file inclusion, reflected XSS and open redirects. Weak-session dispatch generated twenty probes but returned
no captured IDs; this remains incomplete workflow evidence. Scanner tool wrappers now retain binary digests, intended
invocation matches and completion status independently of request dispatch. Aggregate reports require successful
current-pass dependency receipts and source hashes rather than static coverage claims.

Outstanding acceptance includes meaningful workload/concurrency receipts, native scanner completion, per-request
expected responses, scoped fixture restoration, full browser content assertions and all live application layers.
Immutable full-catalog qualification is starting; no accepted full pass, merged installation, clean Terraform rebuild,
sustained-rate acceptance or repeat apply is claimed.

## Installed matrix repair loop

The complete source matrix remains 144 HTTP action contracts, eleven CSD browser contracts, seven connection adapters
and two aggregate reports. Source validation now passes 83 tests and nine subtests; request-response joins, scanner
binary/completion receipts, workload concurrency/connection checks, and wrong-content 200 regression remain enforced.

Native application workflow rerun passed all 33 checks. Installed scraper dispatch passed after pending request drainage,
with no transport failures or cancellations. Hydra qualification passed 99 credential payloads on each of DVWA, Juice Shop
and VAmPI after HTTPS routing and native module-option ordering repair. A measured workload ramp passed 300 requests
across all nine apps at worker levels 1, 10 and 20, with zero transport failures or cancellations. Later source additionally
requires correct application identity and actual measured connection/concurrency behavior; installed rerun is pending.

The first full-matrix candidate pass was interrupted for source repairs after fifteen scenarios, with twelve accepted
launches and three failed browser/Hydra scenarios. It remains an incomplete failed pass. A later pass recorded an
incorrect response expectation for six intentional shadow endpoints: all actions dispatched, but expected 404s were
excluded. Source now explicitly declares 401/404 for those exact negative endpoints. The failed receipt remains failed.
Continuous catalog qualification is running on the next immutable candidate; no complete accepted pass is claimed.

T03/T11 remain in progress because declared contracts do not by themselves prove application workflows, native scanner
completion, expected outcome semantics, scoped fixture restoration, browser screenshots or final clean-deployment
acceptance. All clean rebuild, merged installation, sustained 200-RPS, restart/reboot and repeat-apply gates remain open.

## Post-matrix acceptance hardening

Generator source now passes 85 tests and nine subtests. The source execution matrix still contains all 164 scenarios:
144 request contracts, eleven CSD browser contracts, seven connection adapters and two aggregate report contracts.
Declared response outcomes are joined to exact matched actions, and each required dispatch needs a terminal response.
Aggregate report receipts must match the current source digest. Native scanner invocation/completion, actual workload
concurrency/connection reuse and wrong-content HTTP 200 checks remain separate acceptance assertions.

Installed follow-up passed both the corrected intentional shadow endpoint statuses and a 300-request workload ramp at
levels 1/10/20 across all nine applications, including content identity, actual concurrency and connection reuse, with no
transport failures or cancellations. Hydra dispatched 99 credential guesses per DVWA/Juice Shop/VAmPI endpoint after
native module-option repair. Native workflow rerun passed all 33 application checks. Failed/incomplete full catalog
passes remain failed and were not relabeled. Continuous traffic is running on the next candidate while CI is pending.

Nested worker verification now fails a zero-exit child without observed action receipts. Concurrent child attribution,
fixture mutation restoration, scanner outcome semantics, declared cache behavior, complete rendered navigation and
all required application workflows remain open. No clean rebuild, accepted complete catalog pass, sustained final rate,
merged installation, reboot recovery or zero-change repeat apply is claimed.

## Current candidate checks

Source tests pass 86 tests and nine subtests after extending benign success to require application identity and content
type. Required payload dispatches now need corresponding terminal responses. The latest candidate sources retain the
complete 164-entry matrix; continuous and focused runs preserve failures independently. CI remains pending.

A stronger installed workload ramp passed all nine application identities and measured concurrency/connection reuse
at levels 1, 10 and 20 across 300 requests, with no transport failures or cancellations. The corrected six intentional
shadow endpoint contracts passed their observed 401/404 response expectations. A later full pass failed native browser
credential stuffing on cancellations despite all fifteen credential submits; source now waits for login page resources
before submission and focused retry is pending. These failures are not accepted coverage.

Latest generator source is `1039987738cda33f57cb25d32f616152cddbd4de`. Remaining source-to-live delivery gates
include complete catalog execution, mutation fixture restoration, precise scanner output semantics, nested attribution,
rendered content/workflow completeness, all serving layers, merged artifact installation, clean rebuild, rate/control
qualification and unchanged Terraform repeat apply. No task is completed from source contract presence alone.

## Dynamic cache qualification

Generator revision `83a7386cd5cad4a1ea5f01df28e6a32f733b7458` passes 87 tests and nine subtests, mypy, Pylint,
Ruff and full pre-commit. The query-string and Accept-Encoding scenarios preserve their stable IDs and now verify the
deployed dynamic-bypass behavior, correct application identity and response type, echoed query isolation, and decoded
content instead of requiring cache HIT on authenticated dynamic applications.

Installed qualification passed 72 query-isolation requests including every original user/search/version value, twenty
paired UUID values and alpha/bravo cross-contamination controls. Encoding qualification passed all 24 declared encoding
and no-header cases. Both receipts had zero transport failures and cancellations. Static cache policy qualification,
remaining CDN workload semantics and full catalog acceptance remain open. Continuous traffic is being restarted on this
immutable candidate; no accepted complete pass or final rebuild qualification is claimed.

## Current acceptance receipts

Source tests now pass 89 tests and nine subtests. All 164 scenario execution contracts remain mandatory. Benign traffic
success additionally requires declared content/type identity, each counted payload requires a terminal response, and
undeclared unmatched 500/502/503/504 or transport failures fail the response gate. CDN shell assertions now fail their
process instead of only printing a failure. No failed receipt was relabeled.

The installed dynamic-bypass query and encoding contracts passed 72 and 24 requests respectively, with preserved query
values, application identity and decoded response content. Native credential-stuffing retry passed all fifteen browser
form submits with no transport failure or cancellation after waiting for page resources before submission. Continuous
traffic is enabled and running on the current immutable candidate; the current pass has eight verified scenarios so far.
CI, full catalog acceptance, complete application workflows and the Terraform rebuild/zero-change gates remain open.

## Current full catalog progression

Generator source is `67409fef99dea9635b1cc518f787c4511bc25b90`; validation passes 92 tests and nine subtests,
Ruff, mypy and required pre-commit. The full source matrix is 164 entries across 22 suites, with mandatory request,
browser, connection or report execution evidence. No catalog entry was removed.

The latest continuous pass reached twenty receipts, nineteen accepted launches and a failed baseline load scenario.
Baseline wrk cutoffs cancelled 158 outstanding requests; it remains failed evidence. Source now uses a fixed-count
completion baseline with measured concurrency, connection reuse, per-request content identity and no abandoned
requests. Focused installed qualification is in progress. Remaining baseline randomized-path coverage stays open.

Dynamic query/encoding qualification passed 72 and 24 action/content assertions respectively. Native registration,
contact, credential stuffing, Hydra, scraper, SQL/NoSQL, VAmPI and focused DVWA/RESTaurant dispatch repairs retain their
individual installed receipts. Those do not complete all application workflows or all catalog contracts.

CI source type/format findings in payload-encoding and CDN regression tests were repaired. Current CI is pending.
Continuous traffic will restart after focused qualification. Complete fresh catalog passes, mutation restoration, nested
attribution, scanner semantics, complete rendered workflows, merged installation and clean Terraform acceptance remain
open. T11 is in progress; failed and interrupted passes were not relabeled.

A separate installed baseline completion qualification passed all 200 requests with valid content, actual concurrency
and connection reuse, zero transport failures and zero cancellations. Non-GET bypass qualification passed all nine
request/response/cache-control requirements with zero transport failures/cancellations. Continuous traffic is restarting
on `67409fef99dea9635b1cc518f787c4511bc25b90`; complete catalog and final deployment acceptance remain open.

## Current repair round

Generator source `cd8dfcb4c50d21dc5d32529bdf7259d51494230c` passes 93 tests and nine subtests. Previous revision
`c8d9a00` completed green required CI. All 164 execution contracts remain declared; completion remains gated on installed
and live actions, response semantics, fixture cleanup and complete application workflows.

The latest full pass reached 23 receipts, twenty passing and three failed CDN workloads: multi-client, sustained monitor
and nested maximum load. Those failures remain evidence. Source baseline completion passed installed with 200 finished
requests, measured concurrency/connection reuse and valid app content. Dynamic query/encoding and non-GET bypass
passed installed. Sustained monitor now has a duration/content/cache/completion adapter with focused installed retry
pending; multi-client and nested maximum-load repairs remain open.

Origin recovery source `f27c98eb73dc2edb5f9c05983fe4cb28d42898de` passes 41 tests and 68 subtests. Installed recovery
ownership/readiness passed using pinned running-container labels and exact Compose project/service/working-directory
identity, instead of inspecting an old image object no longer in the Docker cache. The earlier failed ownership probe is
retained. Full immutable origin installation and clean rebuild acceptance remain open.

## Sustained completion and recovery receipts

Focused installed sustained-cache qualification at generator revision `cd8dfcb4c50d21dc5d32529bdf7259d51494230c`
passed 300 requests, declared duration, all six application/cache samples, actual concurrency, connection reuse and
cleanup, with zero transport failures or cancellations. Earlier wrk cutoff and missing-content runs remain failures.
Continuous traffic is restarting on this immutable candidate. Source validation passes 93 tests and nine subtests.

Origin recovery query and running-container provenance repair passed installed ownership/readiness. It requires the
pinned base label, application label, exact container name, Compose project/service and working directory. Unknown
provenance still fails. Origin source validation passes 41 tests and 68 subtests. Immutable full origin installation,
complete workflows and clean rebuild acceptance remain open.

The most recent interrupted full pass had 23 receipts, twenty passing and three failed multi-client/sustained/nested
maximum workloads. Every failed/interrupted pass remains failed. Full two-pass catalog acceptance, scanner semantics,
fixture restoration, nested attribution, rendered completeness, merged-artifact delivery, clean rebuild, sustained-rate
and repeat-apply qualification remain outstanding.

## Multi-client repair qualification

Generator source `50d3ce4ff13e1a97fce76d86861085b81a7ba05f` passes 94 tests and nine subtests, mypy, Pylint,
Ruff and full pre-commit. All 164 source execution contracts remain present. Multi-client source now runs twenty isolated
synthetic clients, each completing five requests, and checks its own returned cookie, True-Client-IP and Fastly-Client-IP.
WAAP sanitizes client-supplied X-Forwarded-For; request dispatch and received forwarding semantics are distinguished.
Installed multi-client qualification is pending. Earlier regex, missing-content, worker and cancellation failures remain
failed evidence. Nested stress attribution and fixture restoration remain open.

Focused installed multi-client qualification passed all 100 requests across twenty clients, each with five identity/cookie
assertions and closed connections. No transport failures or cancellations occurred. This qualifies the bounded identity
adapter; broader nested stress, fixture restoration, rendered completeness and final full-catalog acceptance remain open.
Continuous traffic is restarting on `50d3ce4ff13e1a97fce76d86861085b81a7ba05f`.

## DVGA replica consistency repair

The native browser verifier passed six checks on each of all four replicas, including native paste submission,
subscription delivery and scoped fixture removal. Published HTTP and HTTPS runs exposed unstable replica selection:
three runs missed subscription updates and all four failed cleanup. Those outcomes remain failed evidence.
The four exact synthetic paste objects left by those runs were recovered through native replica requests with title,
content and ID ownership assertions, confirmed removal and a separate private recovery receipt. No failed receipt changed.

The current origin candidate binds browser, GraphQL and WebSocket requests to a replica cookie and retains a private
fixture journal for recovery. Source checks pass 57 tests, type checking and changed-file repository hooks.
Immutable installation and published-layer retry are in progress. Complete catalog and final deployment gates remain open.

## Published DVGA workflow qualification

Origin `a2409bdcc4b6b77d7ada4b32fef22d61fde01306` passed the six-check browser workflow on both domains
over HTTP and HTTPS, including actual subscription delivery and scoped fixture removal. Fifty-four screenshots from
native replicas, origin nginx and published layers were reviewed as a contact sheet, with a full-size form review.
Earlier inconsistent-affinity runs remain failed. This qualifies the declared paste/subscription slice, not all DVGA
features, full scenario scope, or final fresh-deployment acceptance.

The next CSD candidate derives native and published routes and scopes clear-log requests carrying a synthetic fixture
ID to that run while preserving other entries. Source checks pass 58 tests and type checking; installed browser checks
are pending. CSD protection remains disabled. All T01-T16 completion gates remain open.

## CSD browser synchronization repair

The CSD immutable verifier passed five checks through origin nginx with fixture restoration. Concurrent native and
published checks retained fixture-baseline failures, and published checks retained checkout-script cancellation failures.
The verifier now bounds waits, synchronizes the receiver counter, checks the clear response against real receiver state,
and finishes checkout resources before navigation. It retains a private fixture identity journal for interrupted recovery.
Sequential same-source native and published retries remain pending; no failed run was relabeled.

## Sequential CSD workflow qualification

Origin `379fabe55afe057d84ce80f82a82eb4bab551fbc` passed five browser checks on all four native replicas
and both domains over HTTP and HTTPS. Every run verified receiver identity, counter, actual checkout submission,
dashboard, native scoped-clear action and preservation of the pre-existing receiver entries. Earlier overlapping,
resource-cancellation and interrupted runs remain failed evidence. Screenshot contact sheets and a full-size dashboard crop were reviewed; the dashboard renders existing synthetic entries.
Continuous traffic restart is in progress. Complete application/catalog and Terraform acceptance remain open.

## Readiness fixture cleanup

Screenshot review exposed repeated CSD readiness receiver entries. The readiness source now sends a unique fixture ID,
clears only that probe in a finally block and requires its absence. A failing regression reproduced the missing cleanup;
59 source tests and repository hooks now pass. Installed repeated-readiness qualification is pending. Historical
receiver data stays preserved; complete repeat-install and clean-rebuild acceptance remain open.

Installed origin `ea66d4bddc418a3204f24a6488aa865333092f48` passed two consecutive readiness reruns.
Both exited zero and retained the receiver count at 227, confirming the scoped probe leaves no new entry.
The first controller invocation used an unsupported positional argument and remains a failed tool receipt.
This focused idempotence proof does not complete all fixture reruns or final Terraform convergence.

## crAPI published image qualification

The published five-view crAPI verifier passed on the API HTTP domain but failed premature shop image assertions
on the other three layers, while refresh and all view identities passed without browser transport errors. Those runs
remain failed. The source now waits for pending requests and completed image loading before asserting image dimensions.
Pinned immutable installation and fresh published retry are pending. Signup, workshop, MailHog and complete fixture
restoration remain open. Origin readiness repair CI passed all required checks at `ea66d4b`.

Origin `f7ddb6d4bdf9566a9d00ff7266281e7b9bd198e1` passed the crAPI five-view browser verifier on both
domains over HTTP and HTTPS. Every seeded view, shop image and deep-link refresh assertion passed without browser
errors or transport failures. Earlier premature-image assertions remain failed evidence. Signup, additional workshop
workflows, MailHog rendering, comprehensive fixture restoration and final merged/fresh deployment remain open.
Continuous traffic is enabled and running; the current pass has one accepted receipt so far.

## RESTaurant rendered role workflows

The reusable browser verifier executes Swagger OAuth password authentication and actual authenticated GET profile
requests for both seeded customer and chef roles. Those four checks passed live. ReDoc rendered but failed its local
asset assertion because FastAPI still added a Google Fonts style sheet. The adapter now disables external font loading;
60 source tests, type checking and repository hooks pass. Immutable installed verification remains pending while the
active rapid-browsing catalog scenario finishes. No ReDoc or full RESTaurant acceptance is claimed yet.

Rapid browsing remains in progress on installed generator `506d542`: 216 persisted action records include 17 failed
rendered assertions. A source regression also exposed stale 403 evidence incorrectly reused for SPA fragment routes.
Generator `96f2fad` rejects that stale success and performs a fresh navigation when the previous document was blocked.
Seven focused Node tests and repository hooks pass; candidate CI and installed qualification remain pending.
The active older-source run remains untouched for its terminal receipt.

The older-source rapid browser completed all 360 action records and closed Chromium: 111 rendered, 208 mitigation
candidates and 41 failed actions. The result remains failed, including stale-mitigation evidence. No complete catalog
pass is accepted. The next immutable generator has green required CI and rejects stale blocked SPA evidence.
HTTPBin source now derives native assets, specification and form routes from the request prefix; 61 origin source tests
and type checking pass. Its browser verifier requires actual form submit and returned synthetic field values.
Installed qualification is pending after the completed rapid run.

## HTTPBin published form schema repair

The owned API-definition saved plan updated one existing resource and applied successfully. Twelve JSON control
responses passed: valid synthetic JSON returned 200 and missing/wrong demo IDs returned 403 on both domains over
HTTP and HTTPS. Native form submissions still failed. Attributed API-security events identified omitted optional
form fields as non-nullable, so the form schema now explicitly permits empty values while retaining the JSON contract.
A new exact schema upload, ownership-checked plan, apply and published browser retry are in progress. First plan/input
failure and all failed form runs remain preserved. No control or final Terraform convergence acceptance is claimed.

## HTTPBin form acceptance after attributed repair

The corrected nullable form schema applied through a saved ownership-checked plan updating one API definition.
The HTTPBin four-check browser verifier then passed on both domains over HTTP and HTTPS, including actual
form submission and echoed fields, local Swagger assets and the correct specification prefix. All twelve JSON
control cases remained valid: the correct demo ID returned 200, missing/wrong IDs returned 403. Attributed event
evidence identified optional-field nullability in the earlier failure. Those failures and the ambiguous-name upload
remain preserved. Full control attribution and final unchanged Terraform apply remain open.

RESTaurant passed all five rendered role/docs checks on both published domains over HTTP and HTTPS. Native
replica verification and screenshot review are in progress. Continuous traffic is active on `96f2fad`; the current
full catalog pass remains incomplete.

RESTaurant native browser checks exposed 404 at the advertised prefix on every replica despite successful root
responses and generated prefixed documentation. The pinned ASGI adapter now strips only the declared prefix for native
requests. Source checks pass 62 tests and repository hooks. Immutable installation and native/published reruns are
in progress. The earlier native failures remain failed evidence; the catalog pass interrupted for installation remains
incomplete with thirteen accepted receipts.

Origin `f4c8d2f` passed all five RESTaurant browser checks on every native replica. Published reruns retained
intermittent 403 blocks on documentation assets and login, while the HTTPS www layer passed. These are failed
serving-layer evidence and require control attribution; the native prefix adapter does not establish published
acceptance. Continuous traffic restart is in progress.

RESTaurant native replicas and both HTTPS domains passed the five-check workflow after the prefix repair.
Intermittent HTTP failures remain preserved; a fresh synthetic actor live diagnostic passed the www HTTP workflow.
The verifier now assigns a unique opaque actor per run for independent attribution. Immutable installed qualification
for this last verifier change remains pending. No current control attribution was inferred from the transient block.

Generator `808cd6b` adds a second regression distinguishing fresh blocked document probes from stale SPA fragment
evidence; all eight focused Node checks and repository hooks pass. Origin `2e51126` assigns a fresh synthetic
RESTaurant actor per verifier run. Both immutable installs and next installed qualifications are in progress.
All 164 catalog entries remain, and two complete accepted catalog passes are still outstanding.

Installed origin `2e51126` passed the fresh-actor RESTaurant five-check browser workflow on both HTTP domains.
HTTPS rechecks and the focused rapid-browsing retry continue. Required origin CI is green. Complete workflow,
mutation restoration, scanner scope, fresh deployment and final catalog acceptance remain open.

Expanded crAPI mechanic navigation rendered its service form but exposed a root image URL escape on return.
The immutable frontend adapter now anchors vehicle image URLs under the crAPI base and fails if its pinned upstream
source changes. Source checks pass 63 tests and repository hooks. Installed qualification remains pending.
The focused rapid retry has fourteen failures among 216 persisted actions; blank HTTP 200 SPA documents remain
failed despite corrected fresh-versus-stale mitigation handling. The run continues for a terminal receipt.

The focused rapid retry completed 360 records and closed Chromium on generator `808cd6b`, but failed with
54 action failures, unmatched server failures and six cancellations. It remains failed; controller exit zero did
not establish scenario acceptance. Private receipt: `resume-focused-rapid-fresh/pass-focused-1791030621163638487/receipt.json`.
Origin `62d25ed` passed immutable installation and the expanded seven-check crAPI verifier through origin nginx,
including mechanic form navigation and vehicle image return. Published verification is in progress.

The expanded seven-check crAPI workflow passed through origin nginx and both HTTP domains. HTTPS rendered all
seven views but failed a mixed-content redirect at the mechanic list endpoint. The frontend adapter now requests the
canonical trailing-slash endpoint directly, matching native Django routing. Source checks pass 64 tests and repository
hooks; immutable rebuild and HTTPS retry remain pending. Those mixed-content failures remain failed evidence.

Rapid failure records now distinguish attempted from performed actions and retain private response size, script count
and body-character count for failed navigation. Eight focused Node tests and repository hooks pass. Source `3722a58`
is pushed; immutable installed qualification is pending. This diagnostic change does not accept the earlier failed run.

Origin `c55a6ec` passed the expanded seven-check crAPI verifier on both domains over HTTP and HTTPS after the
canonical mechanic endpoint repair. All views, mechanic form, vehicle image return and deep-link refresh checks passed
without browser errors or transport failures. Signup, service-request mutation workflows, MailHog rendering and
comprehensive fixture recovery remain incomplete; this slice does not establish full crAPI acceptance.

Native Juice Shop browser verification failed all four replicas: published frontend API paths returned SPA HTML
with HTTP 200 instead of product JSON. Source adapter now strips the application prefix before native request and
WebSocket dispatch while preserving origin nginx routing and framing repairs. Source checks pass 65 tests and hooks;
immutable installation and native browser retry remain pending. Earlier native failures remain failed evidence.

The next Juice Shop native retry still failed because existing processes retained the old bind-mounted preload inode.
A source configuration digest label now changes the Compose service declaration whenever the preload changes, forcing
container recreation through immutable provisioning. Source checks pass 66 tests and hooks. Installed recreation
and native browser acceptance remain pending; staged file presence was not treated as running-source acceptance.

Origin `e536986` passed immutable installation; the prefixed native Juice Shop product API now returns product JSON.
All four native replicas passed all ten browser checks after adapter-triggered recreation, including products,
images, login, basket, supporting pages and Socket.IO frames. Published rechecks continue.
Continuous traffic restart is in progress. No full catalog or clean deployment acceptance is claimed.

Origin `e536986` passed all ten Juice Shop browser checks on all four native replicas and both domains over HTTP
and HTTPS. Published checks reverified images, login, basket, supporting routes and Socket.IO after container recreation.
The workflow aggregate now additionally reconciles actual HTTP assertions against every manifest workflow and reports
missing assertions; supported HTTP slices remain distinct from complete declared-workflow acceptance.

Installed origin `f99a17f` passed all 33 supported native HTTP checks and correctly reported declared-workflow
acceptance false with explicit missing-workflow lists. Separate browser slices remain evidence requiring a combined
source/layer receipt; the HTTP report alone cannot establish complete coverage.
