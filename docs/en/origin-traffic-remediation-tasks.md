# Origin and traffic remediation tasks

Umbrella: <https://github.com/f5-sales-demo/webapp-api-protection/issues/553>

Implementation issues: [origin-server](https://github.com/f5-sales-demo/origin-server/issues/710), [traffic-generator](https://github.com/f5-sales-demo/traffic-generator/issues/711).

Detailed operational receipts remain in the private lifecycle state directory. Baseline failures are immutable evidence and are not acceptance. Completion requires source, installed, and live checks; all incomplete tasks remain open. Preserve shared DNS, namespace identity, private state, schema fixtures and unrelated worktrees. CSD remains disabled.

## Current acceptance status

This section is authoritative for the resumed repair round. Historical sections below preserve earlier observations;
they do not establish current acceptance. All T01–T16 tasks remain incomplete.

Generator source `3edcadd371784d336645de59ed82ad222c6e94de` preserves all 164 scenarios across 22 suites.
Current source checks pass 105 Python tests, nine subtests and five focused Node tests. Changed-file pre-commit checks
pass. Required CI remains pending. The pinned archive is installed; continuous-service restart is being verified.

Origin `5706801ed48b19f8433874454a142ce8a7c29204` passed the digest-checked immutable release installer and
all native readiness checks. Source checks pass 42 tests and 68 subtests. The private actor-repeat receipt
`actor-repeat-1791010423810835220.json` verifies distinct attacker/victim identities through all four RESTaurant replicas
and stable stored IDs, password hashes, roles and phone values after a repeated seed. Generator source binds those actors
and restores the victim profile on exit, with restoration failure remaining a failed scenario. Full mutation restoration
and installed BOLA scenario acceptance remain open.

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
