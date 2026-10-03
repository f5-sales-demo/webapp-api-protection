# Origin and traffic remediation tasks

Umbrella: <https://github.com/f5-sales-demo/webapp-api-protection/issues/553>

Implementation issues: [origin-server](https://github.com/f5-sales-demo/origin-server/issues/710), [traffic-generator](https://github.com/f5-sales-demo/traffic-generator/issues/711).

Detailed operational receipts remain in the private lifecycle state directory. Baseline failures are immutable evidence and are not acceptance. Completion requires source, installed, and live checks; all incomplete tasks remain open. Preserve shared DNS, namespace identity, private state, schema fixtures and unrelated worktrees. CSD remains disabled.

| Task | Status | Dependencies | Acceptance criteria | Issue / PR | Source revision | Verification receipt |
| --- | --- | --- | --- | --- | --- | --- |
| T01 — Record baseline | In progress | none | Capture routes, replicas, fixtures, rendered failures, catalog, deployed digests, Terraform ownership and shared identities; retain private receipt. | <https://github.com/f5-sales-demo/webapp-api-protection/issues/553>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Pending | Private remediation-baseline/receipt.json; live baseline captured, preservation reconciliation pending |
| T02 — Application manifest | Open | T01 | Exactly nine applications reconciled across declaration, docs, landing, outputs and traffic. | <https://github.com/f5-sales-demo/origin-server/issues/710>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Pending | Pending |
| T03 — Coverage matrix | Open | T02 | Native/published routes, replicas, assertions, fixtures and scenarios; no missing/orphan entries. | <https://github.com/f5-sales-demo/traffic-generator/issues/711>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Pending | Pending |
| T04 — Unified provisioning | Open | T02 | Both roots consume one immutable origin installer including existing pinned dependencies and repairs. | <https://github.com/f5-sales-demo/origin-server/issues/710>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Pending | Pending |
| T05 — Prefix handling | Open | T04 | Assets, links, forms, API, redirects, cookies and SPA routes retain application prefixes. | <https://github.com/f5-sales-demo/origin-server/issues/710>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Pending | Pending |
| T06 — Application defects | Open | T05 | All nine applications pass specified authenticated/seeded/rendered workflows and replica checks. | <https://github.com/f5-sales-demo/origin-server/issues/710>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Pending | Pending |
| T07 — DVWA payload coverage | Open | T03,T08 | All 15 SQLi and 18 XSS payloads reach authenticated DVWA; preserve stable scenario ID mappings. | <https://github.com/f5-sales-demo/traffic-generator/issues/711>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Pending | Pending |
| T08 — Repeatable fixtures | Open | T04 | Synthetic fixture reruns produce no duplicates; scoped mutations restored; blocked setup cannot suppress launches. | <https://github.com/f5-sales-demo/origin-server/issues/710>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Pending | Pending |
| T09 — Content verifier | Open | T03 | Landing reconciliation, navigation, rendered assets/images, console/network, forms and authentication fail closed; screenshots reviewed. | <https://github.com/f5-sales-demo/origin-server/issues/710>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Pending | Pending |
| T10 — Serving layers | Open | T06,T09 | All native replicas, origin nginx, both domains HTTP/HTTPS; identity/type correct; wrong-content 200 fails. | <https://github.com/f5-sales-demo/origin-server/issues/710>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Pending | Pending |
| T11 — Scenario receipts | Open | T03,T07 | 164 entries across 22 suites; intended method/path/payload and browser/connection action observed apart from setup/filler. | <https://github.com/f5-sales-demo/traffic-generator/issues/711>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Pending | Pending |
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

The precise method, endpoint and payload contract is currently implemented for the two DVWA payload scenarios. The remaining catalog scenarios require reconciliation before full-catalog acceptance. Source CI and rendered diagnostics do not complete T11, T15 or T16.

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
