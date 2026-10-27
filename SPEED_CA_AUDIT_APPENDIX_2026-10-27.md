# Speed CA Audit — Appendix: Full Track Findings (27 Oct 2026)

Companion to `SPEED_CA_AUDIT_2026-10-27.md`. Four review tracks, findings verbatim (live-DB verification notes added where production contradicts the repo). File:line references are against `ispeedbiz/speed-ca` @ `f34eb54`.

---

## A. Backend — netlify/functions (55 functions + lib/)

| ID | Sev | Category | Location | Description | Fix |
|----|-----|----------|----------|-------------|-----|
| BE-F1 | **P0** | Tenant isolation / data loss | `settings.mjs:141-152` | `clear_cache` deletes `ai_cache` platform-wide (`.neq('id','00000000-…')`); `clear_chat_history` without client_id same on `chat_history`; with client_id deletes any firm's client unscoped. | Join to `clients.firm_id = auth.firm_id` (or store firm_id on cache rows); enumerate the firm's client ids for the "all" branch. |
| BE-F2 | P1 | Tenant isolation | `chat.mjs:550-558` | Context cache keyed on client_id alone, consulted before the firm check — firm B with a firm-A client UUID gets full context when warm (warmed on every client open, 24h TTL). | Store + check firm_id in `ai_cache`, or verify ownership before cache lookup. |
| BE-F3 | P1 | Tenant isolation | `analyze-document.mjs:105-117` | Document and analyze_all lookups have no firm_id check: cross-tenant analyze (exfiltrates summary, overwrites victim's doc_intelligence). | `.eq('firm_id', auth.firm_id)` on both lookups; reject null firm. |
| BE-F4 | P1 | Tenant isolation | `edit-doc.mjs:46-51` | Document fetched by id only — cross-tenant read of financial JSON sidecar + workbook overwrite via AI edit. | Same scoping fix. |
| BE-F5 | P1 | Portal escalation | `client-context.mjs:25-39` | Portal client's firm_id IS the CA firm's id and that's the only gate — any portal client reads full profile/compliance/doc summaries incl. `ca_only` zone for every client of the firm. | For client_user: require `auth.client_ids.includes(clientId)` + zone filter (mirror chat.mjs). |
| BE-F6 | P1 | Money | `subscription.mjs:369-394` | `verify` never checks order `notes.type`/`notes.firm_id`/amount vs plan price; ₹100 topup payment activates pending Enterprise row; webhook also credits the ₹100. | Require notes.type==='subscription', notes.firm_id match, status paid, amount===plan price; drop subRow fallback. |
| BE-F7 | P1 | Tenant isolation / IP | `genies.mjs` PUT/DELETE/duplicate; `genie-execute.mjs:55-62` | Genie reads/writes unscoped: rewrite/disable/duplicate/execute another firm's genies (system_prompt IP exposed); `{...body}` mass-assignment on update. | Scope reads `is_system OR firm_id=auth.firm_id`, writes `.eq('firm_id',…)`; whitelist updatable columns. |
| BE-F8 | P1 | Storage isolation | `upload-signed-url.mjs:60-97,148-186` | `confirm` never checks path starts with `${client.firm_id}/${client_id}/` — any learned object key registrable as own document, then `download` signs it (service-role bypasses storage RLS). | Enforce the prefix in confirm. |
| BE-F9 | P2 | Auth model | `lib/auth.mjs:78` | `appMeta.firm_id \|\| userMeta.firm_id` — user_metadata is self-editable; accounts missing app_metadata resolve firm from attacker-controlled data; public.users role defaults 'owner'. | Delete the userMeta fallback; fail closed. |
| BE-F10 | P2 | Auth model (systemic) | ~10 endpoints + quota gates | `if (auth.firm_id && …)` idiom: null-firm token skips every tenant check, plan/quota gate, and MCP client reads. (clients.mjs, client-detail.mjs, process.mjs, recompute-compliance.mjs fail closed correctly.) | Central `if (!auth.firm_id) return 403` in requireStaff. |
| BE-F11 | P2 | Secrets / billing | `chat.mjs:114-119`, `edit-doc.mjs:22-28`, `genie-execute-background.mjs:30-38`, `lib/auth.mjs:190-193` | `getApiKey(null)` runs bare `.limit(1).single()` on firm_settings → null-firm caller chats on a random firm's Anthropic key, unmetered. | Null firm → env fallback only; consolidate to one strict helper. |
| BE-F12 | P2 | Money race | `razorpay-webhook.mjs:196-207`, `lib/plan-limits.mjs:299-310` | Ledger credit/debit is read-last-balance-then-insert; dup guard races; concurrent webhook retries double-credit; balance_after drifts. | Unique index on ref; compute balance in SQL/RPC or derive as SUM. |
| BE-F13 | P2 | Money / statutory | `lib/platform-invoice.mjs:36-42` | `nextInvoiceNo()` = count+1 — concurrent payments mint duplicate GST invoice numbers. | Postgres sequence per FY, unique index + retry. |
| BE-F14 | P2 | Portal | `portal-admin.mjs:54-62` vs consumers | `toggle_portal` writes column `enabled`; enforcement reads `portal_enabled`/`is_active`; client-dashboard/client-documents/approval-action never check it — "disable portal" is a no-op. | Fix column; shared `assertPortalActive()`. |
| BE-F15 | P2 | Tenant isolation (writes) | `toggle-na.mjs`, `client-requests.mjs:56-67`, `client-documents.mjs:111-123`, `integrations-oauth.mjs:48-186`, `portal-admin.mjs:84-99`, `invite-client.mjs:22-40` | Body-supplied ids acted on without firm/linkage verification: N/A another firm's tasks, comment on any request, fulfill any doc request, revoke/list others' integrations, link/invite portal users to unverified client_ids. | One-line scoping per endpoint. |
| BE-F16 | P2 | Prompt injection | analyze → doc_intelligence → chat/generate-doc/genies | Client-uploaded docs' AI summaries re-injected verbatim into CA-side system prompts and generated documents; guardrails.mjs only checks genie creation prompts. | Delimited data blocks + "data, not instructions" rubric; cap length; strip imperatives at analyze time. |
| BE-F17 | P2 | Background jobs | generate-doc-background, genie-execute-background | Worker killed at 15-min wall/OOM/deploy → `processing`/`running` rows stranded forever; no sweeper. | Sweep in heartbeat.mjs: >20 min → failed + notification. |
| BE-F18 | P2 | Plan enforcement | `invite-client.mjs`, `ai-usage.mjs:26-30` | invite-client never calls checkPortalAccess (Free firms provision portal); ai-usage lacks requireStaff (portal clients see firm spend). | Add both gates. |
| BE-F19 | P2 | Webhook auth | `telegram-webhook.mjs:17-20` | Fails open when TELEGRAM_WEBHOOK_SECRET unset. | Fail closed (503) like razorpay-webhook. |
| BE-F20 | P2 | Quota race | `lib/plan-limits.mjs` + AI callers | Check-then-act across 5–300s model calls; parallel requests all pass the ceiling. Paid-tier ₹ cap deliberately unenforced (messages-only). | In-flight reservation or post-call hard stop ~120%. |
| BE-F21 | P3 | Correctness | 5 files `auth.userId` (undefined) → activity_log.user_id null; `forbidden({…})`/`unauthorized({…})` passed object-for-req; settings stats not firm-scoped (global volume leak); mcp-server blocks readonly members; genies.mjs `.or()` string interpolation (filter injection, 500s). | Fix typos/signatures; scope stats; escape .or() inputs. |
| BE-F22 | P3 | Duplication | create-admin.mjs dead; getApiKey ×5 divergent; PRICING ×3 (genie-execute copy ignores cache discount); buildContextString ×2; FY logic duplicated; DOC_PROMPTS duplicated sync vs background. | Consolidate on lib/ copies; delete dead code. |
| BE-F23 | P3 | Minor abuse | `lead-capture.mjs:60` upsert lets anyone overwrite a known email's lead; name unescaped into Telegram HTML; `reminder-run.mjs:18` non-timing-safe compare; `upload-signed-url.mjs:48` fy unsanitized in storage key. | Insert-only leads; escape; reuse timingSafeEqualStr; sanitize fy. |

**Sound (verified):** razorpay-webhook HMAC (timing-safe, fails closed, idempotent); worker-token design; mcp-server read-only + firm-scoped; genie ReAct caps + grounding + validators; ~14 endpoints correctly scoped; scheduled functions cron-only; no SSRF; no hardcoded secrets; subscription grace/expiry logic thoughtful.

---

## B. Database — migrations 001–039 + live verification

| ID | Sev (file) | LIVE status | Finding |
|----|-----|------|---------|
| DB-F1 | P0 in repo | **Fixed in prod, open in repo** | 013's `client_users_firm FOR ALL USING (firm_id=firm_id_from_jwt())` would let a portal client UPDATE own `linked_client_ids` → access every client of the firm. Live policy carries `jwt_user_role() <> 'client'` on USING+WITH CHECK — fix applied out-of-band only. |
| DB-F2 | P0 in repo | **Fixed in prod, open in repo** | Same class on `trial_balances`, `bank_transactions`, `ai_credit_ledger`, `client_integrations` (OAuth tokens!), `integration_sync_log`, `firm_genie_prefs`. Live policies verified guarded; migration files are not. Rebuild from repo re-opens everything. |
| DB-F3 | P1 | **Open** | 030 closed the app_config read hole but the exposed live Razorpay webhook signing secret was never rotated. |
| DB-F4 | P1 | **Confirmed live** | 006's users.role CHECK widen swallowed its own failure (`EXCEPTION WHEN others THEN RAISE NOTICE`); live CHECK is still `('owner','sub_user')`. Inserts of ca_user/client_user rejected today. |
| DB-F5 | P1 | **Confirmed live (P0-2)** | 016 trigger selects `c.name FROM clients` — live clients has only company_name; trigger enabled on documents; first client-role upload aborts. Also: live `notifications` shape matches neither 007 nor the repo. |
| DB-F6 | P1 | Open | `firm_id_from_jwt()` / `jwt_user_role()` — the functions every policy depends on — defined nowhere in the repo; 001/006 policies still reference `auth.firm_id()` reading a claim Supabase never emits (dead policies; landmine if the custom token hook is ever enabled — itr_credentials FOR ALL with no role guard). |
| DB-F7 | P1 | Open | ai_credit_ledger: no UNIQUE on ref (webhook retry double-credits), app-computed balance_after races, no amount CHECK, no firm FK. |
| DB-F8 | P1 | Partially resolved live | ~15 live tables have no DDL in the repo (subscriptions, invoices, genies, firm_settings incl. anthropic_api_key, …). Live check: RLS **is** enabled on every public table; policy correctness per table still unauditable from the repo. |
| DB-F9 | P2 | Open | Client-limit trigger is check-then-insert, no lock — concurrent INSERTs exceed the cap. Take `FOR UPDATE` on the firm row or advisory lock. |
| DB-F10 | P2 | Open | 026 prices `*_annual` plan codes that `subscriptions.plan_code` CHECK rejects; entitlement joins would fetch monthly price. Decide plan_code + billing_cycle representation. |
| DB-F11 | P2 | Open | 004 `portal_invites.password` plaintext column; tables absent live (drift) but a rebuild recreates them. Drop. |
| DB-F12 | P2 | Open | 005 references nonexistent `firm_members` and `clients.name` — recorded as applied but cannot have run as written; APPLIED.txt isn't evidence. Store/verify sha256 (027's column exists, unused). |
| DB-F13 | P2 | Open | `seed_compliance_tasks_for_client` SECURITY DEFINER + EXECUTE to authenticated, no firm check on p_client_id — cross-tenant task injection. Also flagged by live Supabase advisor. |
| DB-F14 | P2 | **Fixed live** | 016 function lacked SET search_path in repo; live version has it. Schema-qualify + fix c.name together. |
| DB-F15 | P2 | Open | storage_quotas COALESCE expression index can't serve PostgREST ON CONFLICT (035's incident); add plain UNIQUE (firm_id, client_id) + FKs. |
| DB-F16 | P3 | Note | Migration 009 intentionally absent (superseded draft); document the gap. |
| DB-F17 | P3 | Open | No index containing user_id on ai_usage_log (per-client allowance hot path). |
| DB-F18 | P3 | Open | 003 RUN_IN_DASHBOARD manual step recorded as applied with no verification; custom access-token hook never actually enabled (evidence in 031). Track dashboard steps with verification queries. |

**Live advisor summary (production):** 7 tables RLS-enabled-no-policy (service-role-only — fine); SECURITY DEFINER callable by anon: `get_portal_firm` (internal email check verified — hygiene: revoke anon), `trg_seed_compliance_tasks`; by authenticated: `seed_compliance_tasks_for_client` (DB-F13), `sum_ai_usage(p_firm_id)` (cross-firm usage sums by UUID), `storage_access_allowed`; perf: 22 auth-initplan policies, 117 multiple-permissive-policy warnings (two policy generations coexist), 42 unindexed FKs, 2 duplicate indexes.

---

## C. Frontend — public/ (13 pages, sw.js, manifest)

| ID | Sev | Location | Finding | Fix |
|----|-----|----------|---------|-----|
| FE-F1 | **P0** | `dashboard.html:4077` | `renderMarkdown()` runs DOMPurify with `ADD_TAGS:['button'], ADD_ATTR:['onclick']` — onclick on every element survives; all AI output (chat 4426/6097, genie stream 4990, history 5830) is a stored-XSS channel; with session in localStorage + Anthropic key in memory = takeover. | Default DOMPurify config; event delegation for Copy/doc buttons. |
| FE-F2 | P1 | `dashboard.html:9065-9070` | Global search renders `r.name` (company/task/file names — client-suppliable) unescaped. | `esc()`. |
| FE-F3 | P1 | `dashboard.html:9007,9011` | Analytics top/needs-attention lists render `c.name` raw into innerHTML. | `esc()`. |
| FE-F4 | P1 | `dashboard.html:6766,7400,7615,7653` | Firm's Anthropic key fetched in full (`select('*')` on firm_settings), masked client-side only. | Server returns `{has_key,last4}`; column privilege server-side; write-only from browser. |
| FE-F5 | P2 | `dormant-manager.html:286-301` | Name escaped in cell but injected into `onclick="generate('${name.replace(/'/g,…)}')"` — `"` breaks out; cin/entity_type unescaped. | Pass ids only; escape all. |
| FE-F6 | P2 | `client.html:758-768` | Portal showToast uses innerHTML with file.name/server errors (dashboard copy uses textContent — drift). | textContent. |
| FE-F7 | P2 | auth guards / storage | Client-side-only auth redirect (fine iff RLS airtight); tokens in localStorage; AI chat threads persisted to localStorage per firm; readonly gating "fails open" per its own comment. | Fix XSS first; stop persisting chat; verify server covers every route. |
| FE-F8 | P2 | CDN tags | `marked` fully unpinned (latest), supabase-js `@2` only, zero SRI. | Pin exact + SRI, or self-host. |
| FE-F9 | P2 | all pages | No CSP anywhere; hundreds of inline onclick handlers make one impossible today. | Delegation migration (needed for FE-F1 anyway) then CSP header. |
| FE-F10 | P2 | `auth.html` | No `<form>`: Enter in password field does nothing; weakens password managers. | Wrap in form, type=submit. |
| FE-F11 | P2 | `index.html:26` | `og:image` → og-image.png which doesn't exist; missing og:url/canonical. | Add file + tags + JSON-LD offers. |
| FE-F12 | P3 | client.html/auth.html | Portal has zero ARIA; labels not for-associated; toasts not live regions. | Basic a11y pass. |
| FE-F13 | P3 | `manifest.json:5-6` | PWA start_url=/dashboard.html for all installers — clients double-redirect on every cold start. | Router launch page or per-app manifest. |
| FE-F14 | P3 | `dashboard.html:6012` | Chat appends via `innerHTML +=` — O(n²), destroys live listeners. | insertAdjacentHTML/appendChild. |

**Sizes:** dashboard.html 9,252 lines / 662 KB (~180 innerHTML sinks); client.html 1,517 / 80 KB (30 sinks); index 954; auth 529. **Solid:** sw.js (network-first, zero app-shell caching, zero stale-deploy risk); fetch wrapper (single-flight refresh, one 401 retry); esc() used at the overwhelming majority of sinks; confirm() on all 8 destructive actions; honest marketing copy matching real pricing. **Fragile:** the hand-concatenated rendering layer — every feature is another string, every string a sink dependent on a human remembering esc().

---

## D. QA / CI / process

| ID | Sev | Finding |
|----|-----|---------|
| QA-Q1 | P1 | `check-schema-contracts.mjs` (guard for the platform's biggest defect class) not in deploy.yml nor preflight — manual `npm test` only. |
| QA-Q2 | P1 | Three ungated prod paths: `deploy.sh` (zero checks, missing --functions), `npm run deploy:force`, possible Netlify auto-publish (never confirmed off). |
| QA-Q3 | P1 | Zero automated tests for auth, tenant isolation, RLS, Razorpay — exactly the invariants a service-role architecture needs tested. |
| QA-Q4 | P2 | 5 of 10 CI suites are regex-on-source assertions (pin past bugs; false-green on logic bugs, false-red on renames). |
| QA-Q5 | P2 | Bug-ledger discipline broken: July QA findings (DIR-3 KYC cadence P1, session-refresh race, genie get_client failure, AI fabrication on empty context) never entered BACKLOG; five May rows stuck "awaiting verify"; upload "fixed" May → broken July. |
| QA-Q6 | P2 | Committed scripts hit PRODUCTION: root test_*.mjs POST live endpoints (real AI spend), test-dormant-e2e generates docs for 10 real companies with service key; no staging exists. |
| QA-Q7 | P2 | Inline-script parse gate covers 5 of 13 pages (dormant-manager, install, statics unchecked). |
| QA-Q8 | P2 | Schema snapshots + APPLIED.txt hand-maintained; no freshness check vs migrations. |
| QA-Q9 | P2 | Code auto-deploys on push; migrations manual — preflight's drift check is a soft count-only warning. Deploy should fail/warn loudly on pending migrations. |
| QA-Q10 | P3 | audit-documents-consumers.mjs rots (3 false positives when run); superseded — delete. |
| QA-Q11 | P3 | check.yml duplicates deploy.yml gates with diverging regexes; check red on every push since Aug 5 (comment "Opus model…" at dashboard.html:996 trips the leak grep). |
| QA-Q12 | P3 | COORDINATION.md stale (Apr 2026); dashboard.html:7745 hardcodes a live Razorpay key-id fallback masking env misconfig. |
| QA-Q13 | P3 | Test-cred scheme stores a real owner password in plaintext on disk per HANDOFF instructions; no dedicated low-privilege QA account mandated. |

**Secrets grep:** no real credentials committed anywhere — all embedded JWTs decode to the anon role (public by design); CI secrets via `${{ secrets.* }}`.

**Checks run this audit (offline):** check-schema-contracts PASS (148 writes/200 selects/527 filters/83 enums, 0 violations); pricing-consistency PASS; routing+links+ui-message-channels+free-tier 36/36 PASS; check-inline-scripts PASS (10/10 blocks on 5 pages); audit-documents-consumers FAIL (all 3 findings false positives — confirms rot).

**Top 5 missing tests by risk:** Razorpay webhook signature rejection; automated `.from()` firm-scope static test; schema-contract check on the deploy path; session-refresh race; portal RLS assertions for migration 013.
