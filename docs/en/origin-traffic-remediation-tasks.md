# Origin and traffic remediation tasks

## Current snapshot — 2026-10-04

Umbrella: <https://github.com/f5-sales-demo/webapp-api-protection/issues/553>. Implementation: [origin issue
 #710](https://github.com/f5-sales-demo/origin-server/issues/710), [origin PR
 #711](https://github.com/f5-sales-demo/origin-server/pull/711), [traffic issue
 #711](https://github.com/f5-sales-demo/traffic-generator/issues/711), [traffic PR
 #713](https://github.com/f5-sales-demo/traffic-generator/pull/713), and [WAAP PR
 #554](https://github.com/f5-sales-demo/webapp-api-protection/pull/554). All PRs are drafts and all T01–T16
tasks remain incomplete.

This snapshot records the implementation revisions inspected before documentation reconciliation: origin `9dec3a1e0b18b35e13ceb0d9c71801152f34ae03`, generator `4c2f5287f52d01284418bc5c497d0eea058ead2c`, WAAP `8e13dc52d718fcce5c70bbdf888e375180b78ec3`. Documentation successors require their own CI/rendered build evidence. Full exact-head application and catalog qualification remains open.

The manifest declares nine prefixes and Compose declares 42 container services. The catalog retains 164
scenarios across 22 suites, including the stable 15 SQLi/18 XSS DVWA mappings. **Fourteen functional contracts
are declared; 150 scenarios have no declared functional contract. This count is not live qualification.** All
entries have execution contracts, which are separate from native functional acceptance.

| Evidence layer | Known evidence | Current remaining gate |
| --- | --- | --- |
| Source implementation | Shared installers, prefix adapters, real synthetic fixtures, native tools and fourteen declared functional contracts | Recurring signup actor ownership, remaining complete functional contracts and interrupted mutation recovery |
| Installed verification | `94cc186` origin signup slice; `88010ad` native OTP slice on both domains; `312f665` benchmark workers; `799e360` SSLyze plugin/cleanup slice | Complete exact-source nine-app matrix and all catalog functional contracts; benchmark/video remain unqualified |
| Rendered review | Earlier `dc99bef`: 66 receipts and 315 screenshots; signup slice: twelve manually reviewed screenshots | Complete final-source navigation/assets/forms/actors on every native and published serving layer |
| Final showcase | Provider 13.0.3; both roots validated; saved plans proposed two VM replacements and remain unapplied | Merged upstream archives and installation, preservation reconciliation, clean rebuild, two accepted full passes, attributed controls, restart/reboot and zero-change repeat apply |

Private receipt identifiers include `private-browser-matrix-1791082428479897763`,
`manual-render-review-dc99bef.json`, `resume-native-followups/pass-focused-1791121335656328761/receipt.json`,
and `resume-native-functional-both-domains/pass-focused-1791079166467472534/receipt.json`. Each applies only
to its recorded candidate/scope. Failed login/schema, early screenshot, partial-plugin, dispatch-only,
transport, browser and CI receipts remain failed. Native application rejection does not prove WAAP mitigation.

The checked-in showcase profile/pins must be inspected together with private deployed receipts; variable
defaults alone are not installed provenance. CSD remains disabled (`csd_enabled=false`), with display-only
activity. Keep credentials, cloud IDs, state, mail, raw reports and screenshots private. Fresh full-head PII enforcement on the documentation candidate reported 86 findings outside docs: 43 Terraform,
35 test and eight script findings (61 identifier, 23 email and two home-path categories). Changed-document
enforcement/audit scans are clean. Full repository privacy qualification remains open; older findings and
failed scans remain preserved.

## T01–T16 acceptance table

Source abbreviations: O = origin, G = generator, W = WAAP. All tasks remain incomplete.

| Task | Status | Dependencies | Acceptance criteria | Issue / PR | Source revision | Verification receipt | Remaining work |
| --- | --- | --- | --- | --- | --- | --- | --- |
| T01 — Record baseline | In progress | none | Capture routes, replicas, fixtures, rendered failures, catalog, deployed digests, Terraform ownership and shared identities; retain private receipt. | [webapp-api-protection #553](https://github.com/f5-sales-demo/webapp-api-protection/issues/553); PRs: [origin-server PR #711](https://github.com/f5-sales-demo/origin-server/pull/711); [traffic-generator PR #713](https://github.com/f5-sales-demo/traffic-generator/pull/713) | O `9dec3a1`; G `4c2f528`; W `8e13dc5` | [History](../archive/origin-traffic-remediation-history/); current incomplete | Reconcile preservation baseline |
| T02 — Application manifest | In progress | T01 | Exactly nine applications reconciled across declaration, docs, landing, outputs and traffic. | [origin-server #710](https://github.com/f5-sales-demo/origin-server/issues/710); PRs: [origin-server PR #711](https://github.com/f5-sales-demo/origin-server/pull/711); [traffic-generator PR #713](https://github.com/f5-sales-demo/traffic-generator/pull/713) | O `9dec3a1`; G `4c2f528`; W `8e13dc5` | [History](../archive/origin-traffic-remediation-history/); current incomplete | Verify final landing/output inventory |
| T03 — Coverage matrix | In progress | T02 | Native/published routes, replicas, assertions, fixtures and scenarios; no missing/orphan entries. | [traffic-generator #711](https://github.com/f5-sales-demo/traffic-generator/issues/711); PRs: [origin-server PR #711](https://github.com/f5-sales-demo/origin-server/pull/711); [traffic-generator PR #713](https://github.com/f5-sales-demo/traffic-generator/pull/713) | O `9dec3a1`; G `4c2f528`; W `8e13dc5` | [History](../archive/origin-traffic-remediation-history/); current incomplete | Finish functional/fixture matrix |
| T04 — Unified provisioning | In progress | T02 | Both roots consume one immutable origin installer including existing pinned dependencies and repairs. | [origin-server #710](https://github.com/f5-sales-demo/origin-server/issues/710); PRs: [origin-server PR #711](https://github.com/f5-sales-demo/origin-server/pull/711); [traffic-generator PR #713](https://github.com/f5-sales-demo/traffic-generator/pull/713) | O `9dec3a1`; G `4c2f528`; W `8e13dc5` | [History](../archive/origin-traffic-remediation-history/); current incomplete | Install merged archives in both roots |
| T05 — Prefix handling | In progress | T04 | Assets, links, forms, API, redirects, cookies and SPA routes retain application prefixes. | [origin-server #710](https://github.com/f5-sales-demo/origin-server/issues/710); PRs: [origin-server PR #711](https://github.com/f5-sales-demo/origin-server/pull/711); [traffic-generator PR #713](https://github.com/f5-sales-demo/traffic-generator/pull/713) | O `9dec3a1`; G `4c2f528`; W `8e13dc5` | [History](../archive/origin-traffic-remediation-history/); current incomplete | Verify final prefix routing after rebuild |
| T06 — Application defects | In progress | T05 | All nine applications pass specified authenticated/seeded/rendered workflows and replica checks. | [origin-server #710](https://github.com/f5-sales-demo/origin-server/issues/710); PRs: [origin-server PR #711](https://github.com/f5-sales-demo/origin-server/pull/711); [traffic-generator PR #713](https://github.com/f5-sales-demo/traffic-generator/pull/713) | O `9dec3a1`; G `4c2f528`; W `8e13dc5` | [History](../archive/origin-traffic-remediation-history/); current incomplete | Complete current nine-app matrix |
| T07 — DVWA payload coverage | Open | T03,T08 | All 15 SQLi and 18 XSS payloads reach authenticated DVWA; preserve stable scenario ID mappings. | [traffic-generator #711](https://github.com/f5-sales-demo/traffic-generator/issues/711); PRs: [origin-server PR #711](https://github.com/f5-sales-demo/origin-server/pull/711); [traffic-generator PR #713](https://github.com/f5-sales-demo/traffic-generator/pull/713) | O `9dec3a1`; G `4c2f528`; W `8e13dc5` | [History](../archive/origin-traffic-remediation-history/); current incomplete | Qualify all 33 preserved payloads |
| T08 — Repeatable fixtures | In progress | T04 | Synthetic fixture reruns produce no duplicates; scoped mutations restored; blocked setup cannot suppress launches. | [origin-server #710](https://github.com/f5-sales-demo/origin-server/issues/710); PRs: [origin-server PR #711](https://github.com/f5-sales-demo/origin-server/pull/711); [traffic-generator PR #713](https://github.com/f5-sales-demo/traffic-generator/pull/713) | O `9dec3a1`; G `4c2f528`; W `8e13dc5` | [History](../archive/origin-traffic-remediation-history/); current incomplete | Prove interruption recovery |
| T09 — Content verifier | In progress | T03 | Landing reconciliation, navigation, rendered assets/images, console/network, forms and authentication fail closed; screenshots reviewed. | [origin-server #710](https://github.com/f5-sales-demo/origin-server/issues/710); PRs: [origin-server PR #711](https://github.com/f5-sales-demo/origin-server/pull/711); [traffic-generator PR #713](https://github.com/f5-sales-demo/traffic-generator/pull/713) | O `9dec3a1`; G `4c2f528`; W `8e13dc5` | [History](../archive/origin-traffic-remediation-history/); current incomplete | Review final-source screenshots |
| T10 — Serving layers | In progress | T06,T09 | All native replicas, origin nginx, both domains HTTP/HTTPS; identity/type correct; wrong-content 200 fails. | [origin-server #710](https://github.com/f5-sales-demo/origin-server/issues/710); PRs: [origin-server PR #711](https://github.com/f5-sales-demo/origin-server/pull/711); [traffic-generator PR #713](https://github.com/f5-sales-demo/traffic-generator/pull/713) | O `9dec3a1`; G `4c2f528`; W `8e13dc5` | [History](../archive/origin-traffic-remediation-history/); current incomplete | Verify all final serving layers |
| T11 — Scenario receipts | In progress | T03,T07 | 164 entries across 22 suites; intended method/path/payload and browser/connection action observed apart from setup/filler. | [traffic-generator #711](https://github.com/f5-sales-demo/traffic-generator/issues/711); PRs: [origin-server PR #711](https://github.com/f5-sales-demo/origin-server/pull/711); [traffic-generator PR #713](https://github.com/f5-sales-demo/traffic-generator/pull/713) | O `9dec3a1`; G `4c2f528`; W `8e13dc5` | [History](../archive/origin-traffic-remediation-history/); current incomplete | Complete all native functional contracts |
| T12 — Outcome attribution | In progress | T11 | Explicit negative cases; mitigation, rejection, fixture/tool/transport failure and timeout distinguished. | [traffic-generator #711](https://github.com/f5-sales-demo/traffic-generator/issues/711); PRs: [origin-server PR #711](https://github.com/f5-sales-demo/origin-server/pull/711); [traffic-generator PR #713](https://github.com/f5-sales-demo/traffic-generator/pull/713) | O `9dec3a1`; G `4c2f528`; W `8e13dc5` | [History](../archive/origin-traffic-remediation-history/); current incomplete | Correlate each required control |
| T13 — Lifecycle integration | In progress | T04,T08,T10,T12 | Existing lifecycle/control verbs preserved; immutable inputs/digests/URL maps recorded; startup gated on complete readiness. | [webapp-api-protection #553](https://github.com/f5-sales-demo/webapp-api-protection/issues/553); PRs: [origin-server PR #711](https://github.com/f5-sales-demo/origin-server/pull/711); [traffic-generator PR #713](https://github.com/f5-sales-demo/traffic-generator/pull/713) | O `9dec3a1`; G `4c2f528`; W `8e13dc5` | [History](../archive/origin-traffic-remediation-history/); current incomplete | Verify merged startup/readiness |
| T14 — Repair loop | In progress | T13 | Source checks, installed and live gates pass on committed immutable configuration; failed receipts retained. | [webapp-api-protection #553](https://github.com/f5-sales-demo/webapp-api-protection/issues/553); PRs: [origin-server PR #711](https://github.com/f5-sales-demo/origin-server/pull/711); [traffic-generator PR #713](https://github.com/f5-sales-demo/traffic-generator/pull/713) | O `9dec3a1`; G `4c2f528`; W `8e13dc5` | [History](../archive/origin-traffic-remediation-history/); current incomplete | Close current source/CI/live repairs |
| T15 — Clean rebuild | Open | T14 | One ownership-checked destroy/absence/preservation/recreate from committed source; no manual fixture setup. | [webapp-api-protection #553](https://github.com/f5-sales-demo/webapp-api-protection/issues/553); PRs: [origin-server PR #711](https://github.com/f5-sales-demo/origin-server/pull/711); [traffic-generator PR #713](https://github.com/f5-sales-demo/traffic-generator/pull/713) | O `9dec3a1`; G `4c2f528`; W `8e13dc5` | [History](../archive/origin-traffic-remediation-history/); current incomplete | Prove owned absence/preservation/recreate |
| T16 — Final acceptance | Open | T15 | Two complete catalog passes; 200 aggregate RPS within 5%; 180 benign equally split/rotated across nine apps; >=99% success, zero transport failures; attributed controls; stop/restart/reboot; unchanged apply then zero plan; continuous service running. | [webapp-api-protection #553](https://github.com/f5-sales-demo/webapp-api-protection/issues/553); PRs: [origin-server PR #711](https://github.com/f5-sales-demo/origin-server/pull/711); [traffic-generator PR #713](https://github.com/f5-sales-demo/traffic-generator/pull/713) | O `9dec3a1`; G `4c2f528`; W `8e13dc5` | [History](../archive/origin-traffic-remediation-history/); current incomplete | Two accepted passes; recovery and zero drift |

## Delivery dependencies

Complete upstream implementation gates before merging origin #711 and generator #713. Pin their merged commits
and archive/installer digests in WAAP, prove installed provenance, then complete T15/T16 before merging WAAP
 #554. Required CI, documentation rendering and human showcase acceptance are separate gates. After each merge,
verify Pages publication from that merged revision and published navigation/LLM links.

[Historical archive](../archive/origin-traffic-remediation-history/) preserves the original tracker entries,
including dated failures and narrower successful candidates. It is evidence history, not current acceptance.
[Demo guide](../demo/) documents lifecycle and preservation; [traffic
tracker](https://f5-sales-demo.github.io/traffic-generator/en/continuous-catalog-tasks/) records upstream
outstanding work.

[LLM discovery](../llm-discovery/) links the source-generated text hierarchy.
