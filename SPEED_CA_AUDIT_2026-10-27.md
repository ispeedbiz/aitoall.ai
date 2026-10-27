# Speed CA (ai2all.ai) — Full Platform Audit

**Date:** 27 October 2026 · **Auditor:** Claude Code (autonomous 360° review)
**Scope:** `ispeedbiz/speed-ca` @ `f34eb54` (repo HEAD = live deploy), live site https://ai2all.ai, live Supabase project `jspl-compliance` (ap-south-1), GitHub Actions history, Supabase security/performance advisors.
**Method:** 4 parallel code-review tracks (backend 55 functions, database 39 migrations, frontend 13 pages, QA/CI), live Playwright crawl of every public page, and live-database verification of every P0/P1 claim. Every number below comes from output actually read during this audit.

**What was NOT covered:** the authenticated dashboard/portal interiors in a browser. Owner credentials were supplied mid-audit, but Supabase Auth's CAPTCHA (Cloudflare Turnstile) blocks automated login from this cloud sandbox ("captcha protection: request disallowed") — a good security control doing its job. Inside-app claims rest on code + live DB evidence + the platform's own test suite instead (see §11).

---

## 1. Executive summary

Speed CA is a real, live, honestly engineered product with QA discipline far above typical solo-founder SaaS — real blocking CI, incident-annotated code, honest "UNVERIFIED" labels, a risk register that answers the right question. But tenant isolation is a **hand-written convention on a service-role client, not a mechanism**, and it has been forgotten in roughly a dozen endpoints: one Settings click deletes every firm's chat history platform-wide, a ₹100 top-up payment can activate an Enterprise plan, and firm B can read firm A's client context, documents, and genie prompts by guessing UUIDs. Most damning for the core promise: **no client has ever successfully uploaded a document through the portal — the notification trigger crashes on a column that doesn't exist** (verified live: the trigger is enabled, `clients.name` doesn't exist, and `documents` has 2,158 rows of which zero are `uploaded_by_role='client'`).

The good news: almost every serious finding is a one-to-five-line scoping fix, and the structural fix (a `firmScoped()` helper + fail-closed null-firm rule) is about a day of work. The platform's bones — webhook signature handling, background-worker auth, genie runtime caps, the migration ledger, the schema-contract checker — are genuinely well built.

**Verdict in 3 sentences:** The product works and the engineering culture is the real asset. The security model is one forgotten `.eq('firm_id', …)` away from a cross-tenant breach at all times, and several have already been forgotten. Fix the 4 P0s this week, mechanize tenant isolation this month, and reconcile the repo with production before adding a single new feature.

---

## 2. Architecture & flow (as built)

```
Browser (static HTML, no framework)
  index/auth/dashboard (9,252 lines)/client portal/compliance-calendar
  Supabase JS (anon key) for auth + some direct reads (RLS enforced)
        │
        ▼
Netlify CDN → /api/* → 55 Netlify Functions (esbuild, 60s limit)
  lib/: auth, plan-limits, ai-usage, genie-runtime, guardrails,
        validators, excel/docx builders, rate-limit, invoicing
  Long AI jobs → *-background workers (15 min, HMAC worker token)
        │                       │
        ▼                       ▼
Supabase Postgres (service_role — RLS BYPASSED on this path)   Anthropic API
  firms → users/firm_users → clients → documents,               (firm key →
  compliance_tasks, trial_balances, bank_transactions,           platform key →
  genies/genie_executions, ai_usage_log, ai_credit_ledger,       backup key)
  subscriptions/invoices, notifications, client_users (portal)
        │
        ▼
Razorpay (payments + webhook) · Resend (email) · web-push · Telegram (ops)
```

**The core flow:** CA signs up → trigger creates firm + owner → adds clients (plan-capped by DB trigger) → uploads documents → `analyze-document` extracts `doc_intelligence` via Claude → `recompute-compliance` updates the task radar → genies generate deliverables (NIL financials, secretarial packs, letters) through a ReAct loop with read-only firm-scoped tools, validators, and a corrective loop → client portal mirrors a subset → Razorpay handles plans + AI credit top-ups with auto-generated GST invoices.

**The architectural fact that drives most findings:** every function uses `getServiceClient()` (service-role key). RLS exists and is decent, but it is *bypassed* on the main path — isolation is whatever each endpoint hand-writes. The portal is the exception (client-side anon-key reads), which is why the portal RLS policies are load-bearing there.

---

## 3. Findings by severity

Sources: **BE** = backend review, **DB** = database review, **FE** = frontend review, **QA** = QA/CI review, **LIVE** = verified directly against production this run.

### P0 — fix before anything else

| ID | Where | Finding | Evidence |
|----|-------|---------|----------|
| P0-1 | `settings.mjs:141-152` (BE) | **"Clear cache" / "clear chat history" deletes ALL tenants' data.** `clear_cache` runs `delete().neq('id','00000000-…')` on `ai_cache` and `clear_chat_history` (no client_id) does the same on `chat_history` — platform-wide, service-role, no firm filter. One click by any firm owner destroys every firm's chat history. | Code quoted in backend review; service client bypasses RLS |
| P0-2 | Live DB trigger `on_client_document_upload` (LIVE) | **Client portal uploads crash at the metadata insert.** The enabled trigger's function selects `c.name FROM clients` — live `clients` has only `company_name`. First INSERT with `uploaded_by_role='client'` raises `column c.name does not exist` and rolls back the upload. Verified live: trigger enabled (`tgenabled='O'`), column absent, and `documents` contains 2,145 'ca' + 13 'system' + **0 'client'** rows ever. The portal's core loop has never worked. | `pg_get_functiondef` + `information_schema` + row counts, all read live |
| P0-3 | `dashboard.html:4077` (FE) | **AI output can execute script in the CA's dashboard.** `renderMarkdown()` sanitizes with `DOMPurify.sanitize(html, { ADD_TAGS:['button'], ADD_ATTR:['onclick',…] })` — whitelisting `onclick` on every element defeats the sanitizer. AI output is attacker-influenced (prompt injection via client-uploaded docs → F16 below), so this is stored XSS against the CA. Compounded by P1-4: the firm's full Anthropic key is in page memory to steal. | Code quoted; renders all chat/genie/history output |
| P0-4 | `subscription.mjs:369-394` (BE) | **Enterprise plan for ₹100.** `action=verify` checks the Razorpay signature but never checks the order's `notes.type`, `notes.firm_id`, or amount against the plan price. Buy a ₹100 credit top-up (real payment, valid signature), call `verify` → falls through to the pending row's `plan_code` and activates it. The webhook then also credits the ₹100. | Fallback path quoted in backend review |

### P1 — critical, this sprint

| ID | Where | Finding |
|----|-------|---------|
| P1-1 | `chat.mjs:550-558` (BE) | Context cache keyed on `client_id` alone, checked **before** the firm check — firm B with a firm-A client UUID gets firm A's full client context (PAN, directors, key figures) whenever the cache is warm (warmed on every client open, 24h TTL). |
| P1-2 | `analyze-document.mjs:105-117`, `edit-doc.mjs:46-51` (BE) | No `firm_id` check on document lookups: cross-tenant document analysis (exfiltrates summary, overwrites the victim's `doc_intelligence`) and cross-tenant read/overwrite of financial workbooks via AI edit. |
| P1-3 | `client-context.mjs:25-39` (BE) | **Portal privilege escalation:** a portal client's `firm_id` IS the CA firm's id, and that's the only check — any portal client can pull full profile, compliance state, and `ca_only` document summaries for *every client of the firm* by UUID. (`chat.mjs` and `client-documents.mjs` do this correctly.) |
| P1-4 | `dashboard.html:6766,7653` (FE) | **Firm's Anthropic API key fetched to the browser in full** (`select('*')` on `firm_settings`, masked client-side with `padStart` — the key is in the JSON and in DevTools). Live RLS confirms any firm staff can SELECT it. Exfiltratable by any XSS. |
| P1-5 | `genies.mjs` PUT/DELETE/duplicate, `genie-execute.mjs:55-62` (BE) | Genie reads/writes unscoped: firm B can rewrite, disable, duplicate (prompt IP theft), or execute firm A's custom genies. Mass-assignment via `{...body}` on update. |
| P1-6 | `upload-signed-url.mjs` confirm/download (BE) | `confirm` never checks the storage `path` lies under the caller's firm/client prefix — any learned object key can be registered as your own document and then signed for download (service-role signing bypasses storage RLS). |
| P1-7 | Live `users.role` CHECK (LIVE) | Migration 006's role-vocabulary widen **silently failed in production** (wrapped in a swallow-all exception handler): live CHECK is still `('owner','sub_user')`. Any code path inserting `ca_user`/`client_user` into `users` is rejected today. |
| P1-8 | Migrations 030 (DB) | The Razorpay **webhook signing secret that was readable by any free signup** pre-030 was never rotated — anyone who read it then can forge `order.paid` events now. Rotation is an ops action, not a migration. |
| P1-9 | Repo ≠ production (DB+LIVE) | The intrafirm RLS hardening (role guard on `trial_balances`, `bank_transactions`, `ai_credit_ledger`, `client_integrations` OAuth tokens, `client_users`) **exists only in production** — applied out-of-band, absent from `migrations/`. Verified live: prod policies carry `jwt_user_role() <> 'client'`; the repo files don't. A rebuild from the repo re-opens all of it, and `firm_id_from_jwt()`/`jwt_user_role()` — the security-critical functions every policy depends on — are defined nowhere in the repo. |
| P1-10 | `.github/workflows/deploy.yml` + `scripts/preflight-deploy.mjs` (QA) | `check-schema-contracts.mjs` — the guard for the platform's single biggest historical defect class (silent column/enum mismatches; the July upload P0) — is **not on the deploy path**. A recurrence deploys green today. Three ungated routes to prod exist (`deploy.sh`, `npm run deploy:force`, possible Netlify auto-deploy). |

### P2 — major (selection; full lists in the four track reports)

- **Money races (BE/DB):** `ai_credit_ledger` has no unique index on `ref` (webhook retry double-credits) and `balance_after` is read-then-write (concurrent debits corrupt it). GST invoice numbers are `count(*)+1` — two concurrent payments mint duplicate statutory invoice numbers.
- **Null-firm bypass idiom (BE):** ~10 endpoints check `if (auth.firm_id && …)` — a user whose token resolves no firm (trigger failure; self-editable `user_metadata.firm_id` fallback in `lib/auth.mjs:78`) skips every tenant and quota gate, and `getApiKey(null)` hands them a random firm's Anthropic key, unmetered.
- **Portal disable is a no-op (BE):** `portal-admin.mjs` toggles a column named `enabled`; enforcement reads `portal_enabled`/`is_active`, and `client-dashboard`/`client-documents`/`approval-action` never check it at all.
- **Unscoped writes (BE):** `toggle-na`, request comments, `fulfill_request`, integrations disconnect/list, portal link/invite — each acts on body-supplied ids with no firm/linkage check.
- **Prompt injection (BE):** client-uploaded documents → AI summaries → re-injected verbatim into CA-side system prompts and generated documents. `guardrails.mjs` only checks genie *creation* prompts.
- **Stored XSS misses (FE):** global search results and analytics lists render `company_name`/file names unescaped (client-controlled via portal) — `esc()` exists and is used almost everywhere else; these were missed. Client portal's `showToast` drifted to unsafe `innerHTML` while dashboard's copy is safe.
- **Unpinned CDN supply chain (FE):** `marked` loaded at latest, supabase-js at `@2`, no SRI on any CDN script, no CSP anywhere (the inline-onclick style makes CSP impossible today).
- **No stuck-job recovery (BE):** a killed background worker strands `status='processing'`/`'running'` rows forever; no sweeper exists.
- **No staging (QA):** every E2E verification is a human driving production; committed root scripts POST to live endpoints (`analyze_all:true` = real AI spend) and `test-dormant-e2e.mjs` mutates live data for 10 real named companies.
- **Bug ledger leaks (QA):** July QA report findings (P1 DIR-3 KYC cadence, session-refresh race, genie failures, AI fabrication on empty context) never entered BACKLOG.md; five May rows still "awaiting verify"; the verify loop demonstrably doesn't close (upload "fixed" in May, found 100% broken in July).
- **`check` workflow red since Aug 5 (LIVE):** a code *comment* ("Opus model…", dashboard.html:996) trips the model-name-leak grep — every push shows a failed check, training everyone to ignore red.
- **Real client data in the repo:** `NIL_Financials_Pack*` — financial workbooks for ~11 real named companies committed in triplicate (plus a .zip) at repo root. NIL figures, but real client names/CINs in a git repo is a confidentiality smell and repo bloat.
- **Live advisor results (LIVE):** 22 RLS policies re-evaluate `auth.*()` per row (initplan), 117 duplicate-permissive-policy warnings (two generations of policies coexist on many tables), 42 unindexed FKs, 2 duplicate indexes, no index for the per-user AI-allowance hot path.
- **016/007 migration drift (DB):** `notifications` live shape matches neither migration 007 (never produced it) — repo files cannot rebuild prod; migration 005 references tables that don't exist.

### P3 — polish (selection)

Enter-key doesn't submit the login form (no `<form>` element on auth.html); broken `og:image` on the marketing page (`og-image.png` doesn't exist); PWA `start_url=/dashboard.html` sends installed *clients* through a double redirect; client portal has zero ARIA; `auth.userId` vs `auth.user_id` typos nulling `activity_log.user_id` in 5 files; platform-wide (not firm-scoped) stats on Settings; dead `create-admin.mjs`; 5 divergent copies of `getApiKey`, 3 pricing tables, 2 markdown renderers; stale `COORDINATION.md`; lead-capture upsert lets anyone overwrite a known email's lead data; non-timing-safe token compare in `reminder-run.mjs`; dashboard chat appends via `innerHTML +=` (O(n²)); migration 009 gap unexplained.

### Verified sound (for the record)

Razorpay webhook HMAC (timing-safe, fails closed, idempotent on order+plan); background-worker HMAC auth; genie ReAct loop hard caps + read-only firm-scoped tools + grounding rules + deterministic validators with corrective loop; `clients.mjs`/`client-detail.mjs`/`client-dashboard.mjs`/`team.mjs` and ~10 others correctly scoped; scheduled functions not URL-invocable; no SSRF (allowlisted OAuth endpoints); **no committed secrets anywhere** (anon key only — public by design); sw.js is network-first with zero app-shell caching (zero stale-deploy risk); the global fetch wrapper (single-flight refresh, one safe 401 retry) is better than most framework apps; RLS is enabled on **every** public table (verified live); daily DB backups verified; marketing claims match actual pricing.

---

## 4. Live site crawl results

All 12 public routes crawled with Playwright (screenshots captured): `/`, `/about`, `/auth`, `/contact`, `/compliance-calendar`, `/install`, `/privacy`, `/refund`, `/terms`, `/dashboard`, `/client/portal`, and a 404 probe. **Every page loads (HTTP 200), zero console errors on marketing pages**, extensionless URLs resolve, custom 404 works, `/dashboard` and `/client/*` correctly bounce unauthenticated visitors to Sign In, `/api/heartbeat` refuses unauthenticated calls. The only console noise on auth-gated pages comes from Cloudflare Turnstile (and a `fetch('data:,')` CSP violation originating from the Turnstile/analytics stack — worth a look, likely benign). Deploy state: live site serves repo HEAD `f34eb54` (14 Aug 2026); the Deploy workflow is green, the `check` workflow is red (false positive, see P2).

---

## 5. Feature gap vs competitors (brief, honest)

| Competitor | What they have that Speed CA doesn't | Does it matter? |
|---|---|---|
| TaxDome / Karbon | Email integration, workflow/pipeline automation, e-signatures, time & billing | E-sign (DSC-compatible) matters for Indian CAs; email inbox is a biology-shaped feature — skip it |
| ClearTax / Quicko | Actual filing rails (GST/ITR submission) | The moat question: Speed CA *prepares*, they *file*. Preparation + portal + AI is defensible only until they add AI |
| Suvit | Tally ingestion at scale | Bank import exists; Tally import is the #1 data source for Indian SMB books — real gap |
| Zoho Books | Full accounting ledger | Not the game — Speed CA sits above the ledger. Correct subtraction |

Speed CA's genuinely differentiated surface: compliance radar seeded per entity type, 53 genies producing signed-document-grade deliverables with validators, NIL/dormant financial packs (a real niche nobody serves), the WhatsApp-copyable compliance calendar as lead magnet, and per-firm AI with per-firm keys. That is a coherent wedge.

## 6. Subtraction opportunities

1. **Delete** `create-admin.mjs` (dead), `audit-documents-consumers.mjs` (rotting, superseded), `COORDINATION.md` (stale, misleads agent sessions), the triplicated NIL packs + zip (and get real client names out of git).
2. **Merge:** 5 `getApiKey` copies → 1; 3 pricing tables → `lib/ai-usage`; 2 markdown renderers → 1 shared sanitized renderer; dashboard/client duplicated JS (~101 identical lines) → `speedca-common.js`; 2 CI workflows → 1.
3. **`dormant-manager.html`** duplicates dashboard functionality as a standalone page with its own (weaker) XSS posture — fold it into the dashboard.
4. The biology question applied: the portal's "CA reviews AI entry → approves" loop is right; what should NOT exist is any manual re-keying between extraction and workbook — Blocker 5's trial-balance chain is the pure goal path, finish it rather than adding sidebars.

## 7. AI moat assessment

The intelligence layer is **operationally defensible, not structurally defensible**. Caps, grounding rules, validators-with-corrective-loop, and family-based metering are quality engineering that competitors must re-learn — but prompts are copyable the day someone sees them (and P1-5 currently lets any tenant literally read them). The durable moat candidates are: (a) the **trial-balance + doc_intelligence corpus** accumulating per firm — data gravity; (b) the **validator library** encoding Companies Act/ICAI formatting rules — slow to replicate; (c) distribution via the free tier + calendar lead magnet. Prompt-injection hardening (P2) is a prerequisite for the trust story a CA product sells. Verdict: moat is buildable but today it's a 4/10 — protect the genie store first.

## 8. Billion-dollar scorecard

| # | Dimension | Score /10 | One-line reason |
|---|-----------|-----------|-----------------|
| 1 | Security & tenant isolation | **3** | Convention not mechanism; 4 P0s live; a dozen unscoped endpoints |
| 2 | Data architecture & integrity | **5** | Excellent migration ops undermined by repo≠prod drift and money-path races |
| 3 | Backend engineering | **6** | Strong lib layer, worker auth, webhook handling; duplication re-introduces fixed bugs |
| 4 | Frontend engineering | **5** | Solid SW/fetch infra; 662KB hand-concatenated monolith guarantees F2-class XSS misses |
| 5 | QA & CI discipline | **7** | Real blocking CI, honest UNVERIFIED culture; best check not on deploy path, no staging |
| 6 | Reliability & ops | **6** | Risk register, health probes, background workers; no stuck-job sweeper, red check workflow |
| 7 | Product completeness (Indian CA) | **6** | Radar + genies + portal + billing is a real product; Tally import & e-sign missing |
| 8 | AI capability & guardrails | **6** | Genie runtime is genuinely good; prompt injection from client docs unmitigated |
| 9 | Trust & compliance posture | **4** | For a compliance product: unrotated exposed secret, duplicate GST invoice numbers possible, client names in repo |
| 10 | Moat & defensibility | **4** | Wedge is coherent; prompts stealable today; data moat not yet accumulated |
| | **Total** | **52/100** | Strong foundation, pre-breach security. Not fundable on security DD today — fixable in weeks. |

## 9. Top 10 actions (impact ÷ effort)

1. **Today — P0-1:** firm-scope `clear_cache`/`clear_chat_history` in `settings.mjs` (2 lines). Until then, that button is a loaded gun.
2. **Today — P0-2:** `ALTER FUNCTION notify_ca_on_client_upload` → `c.company_name` in prod + corrective migration. This single fix turns the client portal's core loop ON.
3. **Today — P0-3 + P1-4:** DOMPurify default config (re-wire Copy buttons via event delegation) and stop selecting `anthropic_api_key` to the browser (server returns `{has_key, last4}`).
4. **This week — P0-4:** `verify` must require `order.notes.type==='subscription'`, `notes.firm_id===auth.firm_id`, `amount===plan price`; drop the row fallback.
5. **This week — the scoping sweep:** add `.eq('firm_id', auth.firm_id)` to the ~12 endpoints listed (P1-1/2/3/5/6, P2 writes), plus central `if (!auth.firm_id) return 403` in `requireStaff` and delete the `userMeta.firm_id` fallback. One day, closes the whole class.
6. **This week — rotate the Razorpay webhook secret** (P1-8) and re-run the users.role widen without the exception swallow (P1-7).
7. **This month — make the repo the schema:** dump live `pg_policies` + function defs into a committed snapshot (like columns.json), write the catch-up migration containing the prod-only hardening, define `firm_id_from_jwt()`/`jwt_user_role()` in-repo.
8. **This month — money integrity:** unique index on `ai_credit_ledger(ref)`, SQL-side balance computation, Postgres sequence for GST invoice numbers, background-job sweeper in `heartbeat.mjs`.
9. **This month — wire `check-schema-contracts.mjs` into deploy.yml + preflight**, fix the `check` workflow's comment false-positive, gate or delete `deploy.sh`/`deploy:force`, and add the two regression tests that matter: webhook signature rejection and a static "every `.from()` carries firm scope" test.
10. **Then (not before):** extract `speedca-common.js`, pin + SRI the CDN libs, portal `portal_enabled` enforcement, prompt-injection delimiting for doc-derived text, Tally import on the roadmap.

---

## 10. Functional & output-accuracy verification (what actually ran)

| Check | Method | Result |
|---|---|---|
| Full platform test suite | `node --test tests/*.test.mjs` after clean `npm ci` (scripts disabled) | **92/92 pass** — includes real NIL-financials builder, PY-comparatives Excel round-trip, P&L extraction, DOCX/XLSX byte+content verification, AI validator/guardrail evals |
| Schema contracts | `check-schema-contracts.mjs` | PASS: 148 write payloads, 200 selects, 527 filters, 83 enum literals, 0 violations |
| Generated workbook accuracy | ExcelJS inspection of committed NIL pack (CARETEAM FY25-26) | Correct 7-sheet structure (Cover→AOC-4 Data), all FY labels correct (FY 2025-26, "as at 31 March 2026", PY 2024-25), correct NIL narrative — the old FY26-27 labeling bug is absent. Auditor signature fields not present in this pre-Aug-5 sample (that bug was fixed 5 Aug; regenerate samples to confirm) |
| GST invoice numbering (live) | SQL on `platform_invoices` | **0 duplicate invoice numbers**, 0 zero-total invoices (the race is latent, not yet materialized) |
| AI credit ledger (live) | SQL: sum(amount) vs last `balance_after`, duplicate refs | **0 drift, 0 duplicate refs** (races latent at current volume) |
| Background jobs (live) | SQL: stale `processing`/`running` rows | 0 stuck right now (no sweeper exists — see P2) |
| AI metering (live) | SQL on `ai_usage_log` | **36 of 143 rows (25%) have firm_id NULL** — unattributed/unbillable AI spend, confirming the background-worker metering gap in production |
| Document pipeline (live) | SQL on `documents` | 2,158 docs: 413 ready, **1,739 (80%) status 'pending'** (never analyzed), 5 failed — the analyze pipeline is barely exercised |
| Platform scale (live) | SQL | 11 firms, 79 clients, 620 compliance tasks, 53 genies, 17 genie executions (all completed) |
| Public pages | Playwright crawl | 12/12 load clean (details §4) |
| Authenticated walkthrough | Playwright + owner creds | **Blocked by Supabase Auth CAPTCHA from this sandbox** — to complete it: temporarily disable Auth → CAPTCHA in the Supabase dashboard, or drive it from a normal browser using the Phase-2 screenshot flow of the testing skill |

## 11. Track reports

The four detailed findings tables (backend F1–F23, database F1–F18, frontend F1–F14, QA Q1–Q13 + coverage map) are preserved in full in the audit working notes and can be committed alongside this report on request. Everything P0/P1 from them is reflected above, with live-DB verification results applied (two DB P0s were found already fixed in production and downgraded to the repo-drift finding P1-9; two were confirmed live and promoted: P0-2, P1-7).
