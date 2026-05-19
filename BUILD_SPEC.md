# Screen Watermarking SaaS — Build Specification

A productionizable design for an enterprise screen-watermarking platform based on the Gugelmann et al. (2018) screen watermarking technique, adapted for multi-tenant SaaS deployment.

---

## 1. Product Concept

**Name (working):** *Tracemark* (placeholder — replace with branded name)

**One-liner:** Deploy invisible, per-session screen watermarks across an organization's workstations so that any photograph of a screen — even cropped, compressed, or shot at an angle — can be traced back to the workstation, user, and minute it was displayed.

**Buyer:** CISO / Insider Risk / DLP program owners at companies with high-value IP (financial services, defense contractors, pharma, legal, media pre-release).

**Distribution:**

- Endpoint agent installed via MDM (Intune, Jamf, Kandji, Workspace ONE)
- Cloud-hosted backend (single-tenant or multi-tenant)
- Web-based admin console and forensic portal

**Pricing model:** Per-endpoint / per-month, with tiered features (basic attribution → SSO/SIEM/compliance pack → on-prem deployment).

---

## 2. System Architecture

```
┌─────────────────────┐         ┌────────────────────────────────────┐
│  Workstation        │         │  Backend (multi-tenant SaaS)        │
│                     │         │                                     │
│  ┌───────────────┐  │  HTTPS  │  ┌──────────────┐  ┌─────────────┐ │
│  │ Endpoint      │◄─┼─────────┼─►│ Token Issuer │◄─┤ KMS / HSM   │ │
│  │ Agent         │  │ (mTLS)  │  └──────┬───────┘  └─────────────┘ │
│  │               │  │         │         │                          │
│  │  ┌─────────┐  │  │         │  ┌──────▼───────┐  ┌─────────────┐ │
│  │  │ Render  │  │  │         │  │ Session DB   │  │ Audit Log   │ │
│  │  │ Overlay │  │  │         │  └──────────────┘  └─────────────┘ │
│  │  └─────────┘  │  │         │                                     │
│  │  ┌─────────┐  │  │         │  ┌──────────────┐  ┌─────────────┐ │
│  │  │ Identity│  │  │         │  │ Policy Svc   │  │ Identity    │ │
│  │  │ Binder  │  │  │         │  └──────────────┘  │ (SSO/SCIM)  │ │
│  │  └─────────┘  │  │         │                    └─────────────┘ │
│  │  ┌─────────┐  │  │         │  ┌──────────────────────────────┐  │
│  │  │ Watchdog│  │  │         │  │ Forensic Extraction API      │  │
│  │  └─────────┘  │  │         │  └──────────────┬───────────────┘  │
│  └───────────────┘  │         │                 │                  │
└─────────────────────┘         └─────────────────┼──────────────────┘
                                                  │
                                ┌─────────────────▼──────────────────┐
                                │  Admin / Investigator Web Console  │
                                │  - User & device mgmt              │
                                │  - Policy config                   │
                                │  - Photo upload → extraction       │
                                │  - Audit trail                     │
                                └────────────────────────────────────┘
```

**Data flow at a glance:**

1. User logs into workstation. Agent authenticates to backend (mTLS + device cert).
2. Backend issues a short-lived **session token** (40-bit opaque ID) and a derived **MAC key** for that user.
3. Agent uses the token + key to build the 64-bit payload, runs the encoder, generates the overlay mask, and renders it via GPU shader.
4. Token rotates every N minutes (default: 5). Each rotation creates a new audit-log row server-side mapping token → (tenant, user, device, time window).
5. Investigator uploads a recovered photo. Backend de-skews, extracts symbols, runs Viterbi decode, looks up token, verifies HMAC, returns attribution.

---

## 3. Core Algorithm Library

This is the heart of the product. Build it once, in a portable native language (Rust recommended), and expose it via FFI to all agent platforms and to the backend extraction service.

### 3.1 Payload design

The watermark payload is **64 bits total**:

| Field      | Bits | Purpose                                                       |
|------------|------|---------------------------------------------------------------|
| `token`    | 40   | Opaque random session token; server-side lookup               |
| `mac`      | 24   | Truncated HMAC-SHA256 over token, using per-session MAC key   |

**Why opaque tokens?** It would be tempting to encode tenant+user+device+timestamp directly. Don't. An opaque token has three advantages:

- It leaks nothing on its own — the attacker who reverse-engineers the encoding gets a number with no semantic content.
- Revocation, expiry, and key rotation are server-side bookkeeping.
- The payload stays small (more error-correction budget).

**Forgery resistance:** 24-bit MAC means ~1-in-16-million chance of a blind forgery per attempted submission. With per-tenant rate limiting on the extraction API (e.g., 10/hour for a real investigation), this is sufficient. Bump to 32-bit MAC if your threat model warrants it.

### 3.2 Convolutional encoder with split sub-watermarks

Per the paper's design, use a **rate-1/2 convolutional code with constraint length K=15**. The novelty is *not* merging the two generator polynomials into one codeword — instead emit two independent sub-watermarks, then repeat the whole encoding three times with different seeds to get **6 sub-watermark blocks**.

**Encoding flow:**

1. Take 64-bit payload `P`.
2. Pad with K-1=14 zero "termination" bits → 78 bits.
3. Run through two generator polynomials g₁ and g₂ → two 78-bit blocks, B₁ and B₂.
4. Permute B₁ and B₂ with three different seeded shuffles → six total blocks of 78 symbols each.
5. Total physical bits: 6 × 78 = **468 symbols**.

The polynomials should be optimized via evolutionary search against an empirical BER model (the paper does this; you'll re-do it once you have field BER data). Start with the known-good (171, 133) octal pair for K=7 as a working baseline.

**Why six blocks?** Because each block independently carries the full payload, the decoder can pick whichever blocks are least corrupted by cropping/glare and reconstruct from as few as one (with luck) or 3-4 (typical). This is the property that makes the system robust to partial pictures.

### 3.3 Symbol overlay rendering

Each symbol is a **32×32 pixel circular gradient**:

- **Inner disk** (radius `r1` ≈ 4px): luminance shifted by Δ (positive for bit=0, negative for bit=1)
- **Transition annulus** (radius `r2` ≈ 12px): smooth cosine falloff from Δ to 0, with low-amplitude white noise (~Δ/4) added
- **Outer area**: untouched (acts as the local reference for differential decoding)

Default intensity Δ = `(2, 2, 2)` (RGB additive). The paper found `(3,3,3)` invisible in text areas and `(1,1,0)` invisible on white background; you'll calibrate per-display per the policy service.

**Mask generation:**

```
mask = zeros(screen_width, screen_height, 4)  # RGBA
grid_cols = screen_width // 32
grid_rows = screen_height // 32
for i, bit in enumerate(encoded_bits):
    col, row = i % grid_cols, i // grid_cols
    cx, cy = col*32 + 16, row*32 + 16
    sign = +1 if bit == 0 else -1
    for y in range(cy-16, cy+16):
        for x in range(cx-16, cx+16):
            d = sqrt((x-cx)**2 + (y-cy)**2)
            if d < 4:
                mask[x,y] = sign * delta
            elif d < 12:
                falloff = 0.5 * (1 + cos(pi * (d-4)/8))
                mask[x,y] = sign * delta * falloff + noise()
```

This mask is pre-computed once per token rotation (every 5 minutes), cached, and uploaded to GPU. Real-time work is just an additive blend in a fragment shader.

**Important:** Use luminance-only modulation in a perceptually-uniform color space (Oklab or CIELAB), then convert back to sRGB. Doing additive RGB shifts in sRGB causes chromatic artifacts in dark colors.

### 3.4 Symbol extraction

From an uploaded photograph:

1. **De-skew**: detect screen edges via Hough transform or learned edge detector; warp to a rectified screen-space image.
2. **Grid registration**: locate anchor markers (small black dots at the four corners of each block — the paper notes they look like dead pixels). Use them to register the symbol grid.
3. **Per-symbol decision**: for each 32×32 cell, compute median luminance of the center 8×8 region (A1) and the surround ring (A3). Bit = 0 if `mean(A1) > mean(A3)`, else 1. Confidence = `|mean(A1) - mean(A3)| / σ(A3)`.
4. **Output**: bit array of length 468 with per-bit confidence scores.

The confidence scores feed into the Viterbi decoder as soft inputs, which dramatically improves error correction vs. hard decisions.

### 3.5 Soft-decision Viterbi decoding

Standard Viterbi with the constraint-length-15 trellis. For each of the 6 sub-watermark blocks:

1. Run Viterbi independently on the 78 bits → candidate 64-bit payload.
2. Split into token + MAC; look up token in DB.
3. If token exists, fetch the MAC key, recompute MAC, compare.
4. If MAC matches → success, return attribution.

If no single block succeeds, try **block combining**: for each pair of blocks that came from the same encoded stream (B₁ + B₂ pre-permutation), combine their soft outputs before Viterbi. Per the paper's Monte Carlo, this lifts success probability past 98% even at 30% BER.

---

## 4. Endpoint Agent

The agent must: (a) render the overlay continuously and imperceptibly, (b) bind to the logged-in user identity, (c) resist tampering, (d) phone home for token rotation and config.

### 4.1 Rendering pipeline

Use the OS-native compositor APIs. Do **not** use Electron or a browser-based overlay — it'll lag, drop frames, and be trivially defeated.

**Windows:**
- DirectComposition / DWM with a topmost layered window covering the desktop.
- Per-pixel alpha (`UpdateLayeredWindowIndirect`), with the overlay texture set as a Direct3D 11 resource.
- Composition runs in GPU; overhead is <1% CPU on modern hardware.

**macOS:**
- CGS private API window at `kCGOverlayWindowLevel` covering the active screen.
- Metal shader for the overlay blend.
- Requires Screen Recording permission (entitlement granted via MDM profile).

**Linux:**
- X11: compositing window with `_NET_WM_STATE_ABOVE` and `_NET_WM_WINDOW_TYPE_NOTIFICATION`, XComposite extension.
- Wayland: harder — requires a compositor plugin (wlroots-based) or a privileged Pipewire stream. Wayland is the long-pole; document as Phase 2 support.

**Multi-monitor:** render per-display, with per-display token (so a leak from monitor 2 can be distinguished from monitor 1). Account for DPI scaling and HDR displays (HDR needs separate calibration of Δ since headroom math differs).

### 4.2 Identity binding

The watermark is only useful if `(token → user, device, time)` is reliable.

- Agent runs as a system service.
- On user login (via OS hook: Windows session events, macOS `loginwindow` notifications, Linux PAM), bind active SID/UID to the agent's current session.
- Request new token from backend with `(device_cert, user_id, timestamp)`.
- For shared workstations, rotate token on session switch.
- For RDP/Citrix/VDI, render on the virtual session — agent must distinguish between console and remote sessions and emit different tokens.

### 4.3 Anti-tampering

A determined insider will try to kill or hook the agent. Defenses:

- **Service protection**: Windows protected process light (PPL) or kernel-mode mini-driver; macOS Endpoint Security framework. Prevents user-mode termination.
- **Watchdog process** in a separate process tree that restarts the renderer if it dies and posts an alert to backend.
- **Health beacon**: agent sends heartbeat with rendering proof (hash of the most recently composed frame's mask region). Backend flags missing heartbeats.
- **Tamper-evident logging**: every agent action signed with the device key; backend rejects gaps in the sequence number.
- **Display capture detection**: hook `SetWindowsHookEx`, screen capture APIs, etc. — log when a screenshot or screen recording happens. (Not for prevention; for correlation with future leaks.)

You will not prevent a root-level adversary from disabling the agent. The goal is to (a) make it costly and slow, (b) guarantee the security team gets an alert when it happens, and (c) ensure that the *absence* of a watermark on a leaked photo is itself a strong signal.

### 4.4 Update mechanism

Sparkle (macOS), Squirrel/Omaha (Windows), or a custom updater. Signed updates, staged rollout, automatic rollback on health failure. MDM-pinned for enterprise installs.

---

## 5. Backend Services

Microservices, but resist over-decomposition. Five services is plenty.

### 5.1 Identity / Auth Service

- OIDC + SAML 2.0 for enterprise SSO (Okta, Azure AD, Google Workspace, Ping).
- SCIM for user provisioning/deprovisioning.
- Device enrollment via certificate (issued during MDM-driven install).
- mTLS for all agent ↔ backend traffic.

### 5.2 Token Issuance Service

The hot path. Must be fast (<50ms p99) and never lose audit data.

- Endpoint: `POST /v1/sessions` → returns `{token, mac_key, ttl, next_rotation_at}`.
- Token: 40-bit cryptographically random integer. Uniqueness check against a Bloom filter + DB.
- MAC key: derived per-session via `HKDF(tenant_master_key, token || user_id || device_id)`. The tenant master key never leaves the KMS.
- Logs `(token, tenant_id, user_id, device_id, issued_at, expires_at)` to the session DB synchronously before returning. Audit log is the source of truth for attribution.

### 5.3 Key Management

Use a managed KMS (AWS KMS, GCP KMS, or for high-trust customers, dedicated HSM via CloudHSM / Equinix SmartKey).

- Per-tenant master key, never exported, only used for `HKDF` derivation operations via KMS-internal API.
- Key rotation: scheduled annually plus on-demand. Old keys retained for forensic decryption of historical photos.
- Optionally: customer-managed keys (BYOK) for high-security enterprise customers.

### 5.4 Policy Service

Per-tenant, per-device-group, per-application policy:

- Watermark intensity (default vs. high-contrast displays)
- Symbol size (default 32×32, fall back to 24×24 on small displays)
- Token rotation interval (default 5 min, configurable 1-60 min)
- Excluded apps (e.g., games, video players where the overlay would be too visible)
- Always-on apps (force watermarking even if user toggles)

Policy delivered to agent on heartbeat; cached locally with signature.

### 5.5 Forensic Extraction API

Investigator uploads photo → returns attribution.

- `POST /v1/extract` with multipart image upload.
- Authenticated against investigator role with audit trail (who extracted what, when, why — case ID required).
- Pipeline: preprocessing → symbol extraction → Viterbi decode → token lookup → MAC verify → response.
- Returns: `{tenant, user, device, time_window, confidence, audit_id}` or detailed failure reason.
- Heavy operation (5-30 seconds per photo) — run async with job queue; return job ID and poll.

### 5.6 Audit Log

Every meaningful action (token issue, agent install, policy change, extraction request, MAC verification) goes to an append-only log. Use a write-once store (S3 Object Lock, GCS bucket lock) or a tamper-evident chain (Merkle log à la AWS QLDB) for compliance.

This log is part of your product's value: it's what stands up in court.

---

## 6. Forensic Extraction Tool

The web-based investigator UI. Likely the second-most-important UX surface after the admin console.

**Workflow:**

1. Investigator logs in (MFA enforced).
2. Creates a "case" with metadata (incident ID, requester, justification).
3. Uploads photo(s). Supports JPG, PNG, HEIC, PDF (extracts pages), screenshots-of-photos (yes, people do this).
4. System runs preprocessing pipeline and shows the de-skewed, gridded image side-by-side with raw upload.
5. Extraction progress shown live (which blocks decoded, which failed).
6. Result displayed: `User X was logged into Device Y between 14:35-14:40 on 2026-03-15`. With confidence score and audit ID.
7. Investigator can export evidence package (image, decode metadata, audit trail, signed PDF report) — chain-of-custody hash chain.

**Edge cases to handle gracefully:**

- Photo of a photo (degraded but often still decodable with 1-2 blocks)
- Photo cropped to a single paragraph (block selection must be flexible)
- Photo from extreme angle (>45°) — preprocessing fails, surface a manual rectification UI
- Photo from a non-watermarked workstation — return "no watermark detected" rather than a false attribution
- Multiple overlapping screen images (e.g., a Slack screenshot of a photo) — try to detect the outermost screen first

---

## 7. Admin Console

Standard SaaS admin surface, built on the same React stack you already use for client dashboards.

**Core views:**

- **Fleet:** all enrolled devices, status (active/idle/offline/tampered), last heartbeat, current policy.
- **Users:** SSO-synced user list with linked devices, watermarking history.
- **Policies:** policy builder UI with per-OU/per-group rules. Preview pane shows what a watermarked screen looks like under the policy.
- **Incidents:** integration with extraction results — opened cases, status, attribution outcomes.
- **Compliance:** export audit logs, run access reports, key rotation status.
- **Health:** agent error rates, decode success rates by display model (drives policy auto-tuning).

---

## 8. Data Model

PostgreSQL primary, with the audit/event firehose into BigQuery for analytics (matches your existing stack).

**Tables (simplified):**

```sql
tenants(id, name, created_at, kms_key_arn, plan, ...)
users(id, tenant_id, sso_subject, email, created_at, ...)
devices(id, tenant_id, user_id, hostname, os, cert_thumbprint, mdm_id, ...)
policies(id, tenant_id, scope, intensity, symbol_size, rotation_interval, ...)
sessions(token, tenant_id, user_id, device_id, mac_key_ref, issued_at, expires_at)
  -- token is the 40-bit lookup key; index on (token) PRIMARY
audit_events(id, tenant_id, event_type, actor_id, target_id, payload_jsonb, ts)
extractions(id, tenant_id, investigator_id, case_id, image_hash, result_jsonb, ts)
```

`sessions` will be the high-volume table. At 5-min rotation, 8 work hours, 1000 devices = ~100k rows/day. Partition by month. Archive >2 years to cold storage.

---

## 9. Tech Stack Recommendations

Given your existing stack (TypeScript, Python, BigQuery, React) and the performance requirements:

| Layer                  | Tech                                                  | Rationale                                                  |
|------------------------|-------------------------------------------------------|------------------------------------------------------------|
| Core algorithm library | Rust                                                  | Native perf, FFI to all agent platforms, memory safety     |
| Endpoint agent shell   | Rust + per-OS native (C++/Swift/ObjC for OS APIs)     | One codebase for logic, native bindings for compositors    |
| Backend services       | TypeScript (Node 20 + Fastify) or Python (FastAPI)    | Match team skills; both fine for this load                 |
| Extraction worker      | Python + OpenCV + Rust algo library via PyO3          | OpenCV ecosystem is unmatched for image preprocessing       |
| Admin/Investigator UI  | React + Vite + Tailwind + shadcn/ui                   | Your existing stack                                        |
| Database               | PostgreSQL 16                                         | Standard; works with all clouds                            |
| Analytics warehouse    | BigQuery                                              | Your existing infra; audit log analytics                   |
| Object storage         | S3 / GCS                                              | For uploaded images, evidence packages, exports            |
| KMS                    | AWS KMS or GCP KMS, CloudHSM for premium tier         | Compliance-grade key custody                               |
| Job queue              | NATS or AWS SQS                                       | For async extraction jobs                                  |
| Auth                   | Auth0 or WorkOS (for SAML/SSO heavy lifting)          | Don't roll your own enterprise SSO                         |
| Infra                  | Terraform + AWS (or GCP)                              | Multi-AZ; consider AWS GovCloud for defense customers      |
| Observability          | Datadog or Grafana Cloud                              | Standard                                                   |

---

## 10. Build Phases

A 12-month roadmap to a sellable v1.

### Phase 0: Algorithm validation (1 month)
- Build the core algorithm library (Rust) — encoder, decoder, symbol render, symbol extract.
- Validate end-to-end with the same lab setup as the paper: display a watermarked image on a real screen, photograph with 4-5 phones, prove BER ≤ 25% and successful decode.
- **Exit criterion:** photographed watermarks decode reliably (>95% success on raw, >90% on resized).

### Phase 1: Single-platform MVP (2 months)
- Windows agent (largest enterprise market).
- Minimal backend: token issuance, KMS, session DB.
- CLI extraction tool (no UI yet).
- Deploy to your own machines for dogfooding.
- **Exit criterion:** can install on a laptop, photograph the screen, identify which laptop and when.

### Phase 2: Backend hardening + Admin console (2 months)
- Multi-tenancy, SSO (Auth0 or WorkOS), SCIM provisioning.
- React admin console for fleet management.
- Audit log infrastructure.
- mTLS device enrollment via MDM (Intune integration first).
- **Exit criterion:** can onboard a 50-device pilot customer.

### Phase 3: macOS agent + Investigator UI (2 months)
- Native macOS agent with Metal shader.
- Web-based forensic extraction tool.
- Evidence packaging with chain-of-custody.
- **Exit criterion:** pilot customer can run a real investigation start-to-finish.

### Phase 4: Compliance + scale (2 months)
- SOC 2 Type I.
- BYOK / customer-managed keys.
- HDR display calibration.
- Multi-monitor and VDI support (Citrix, AVD).
- BigQuery audit log pipeline.
- **Exit criterion:** can close enterprise deals requiring SOC 2 and BYOK.

### Phase 5: Linux + advanced features (2 months)
- Linux agent (X11 first, Wayland later).
- SIEM integrations (Splunk, Sentinel, Chronicle).
- Anomaly detection (e.g., agent disabled events).
- Print watermarking module (yellow dot equivalent for organizations that allow printing).
- **Exit criterion:** SOC 2 Type II audit period started, three customers in production.

### Phase 6: Differentiation (1 month + ongoing)
- AI-augmented decoding: train a small model to do symbol extraction directly from photos, robust to motion blur and glare.
- Mobile screen watermarking module (for BYOD environments).
- Pre-release content workflow (Hollywood / publisher use case).

---

## 11. Threat Model & Security Considerations

### Adversaries

| Adversary             | Goal                                                       | Mitigation                                                |
|-----------------------|------------------------------------------------------------|-----------------------------------------------------------|
| Casual insider        | Photograph screen, share to outside party                  | Watermark survives; attribution works                     |
| Aware insider         | Knows watermarking exists, tries to defeat it              | Anti-tamper, integrity logs, MAC prevents forgery         |
| Sophisticated insider | Reverse-engineers algorithm, attempts forgery              | MAC + per-session keys; forgery requires server access    |
| Collusion             | One employee uses another's logged-in machine              | Combine with biometric session attestation; SSO step-up   |
| External attacker     | Compromises backend to issue malicious tokens              | KMS isolation, RBAC, audit log, anomaly detection         |

### Privacy considerations

- The watermark itself contains no PII — just an opaque token. PII is only in the backend, gated by access controls.
- Forensic extractions are themselves audited and require investigator authentication.
- Customers should disclose watermarking to employees per jurisdiction (GDPR Art. 13 in EU; Illinois BIPA-style notice in some US states).

### Specific attacks worth thinking through

- **Replay attack**: attacker photographs a colleague's screen, then submits it claiming it was their own. The MAC validates as long as the colleague was logged in — attribution will (correctly) point to the colleague. This is why the system must be combined with CCTV/access logs to disambiguate physical presence. Mention this clearly in customer documentation.
- **Frame attack**: attacker extracts a watermark from victim's screen and overlays it onto a different document. The watermark says "X displayed *something* at time T" — not "X displayed *this specific document* at time T". Workstation event logs (file access logs from the OS) close this gap.
- **Display-driver compromise**: an attacker with admin can hook the compositor and strip the overlay. Detectable via the rendering-proof heartbeat (server expects a hash of the actual composited output, agent provides it, divergence = alert).

---

## 12. Compliance & Legal

- **SOC 2 Type II** is table stakes for enterprise.
- **ISO 27001** for international customers.
- **FedRAMP Moderate** if pursuing US federal customers (long process, 18+ months).
- **GDPR/CCPA**: data minimization in audit logs, DPA template, EU data residency option.
- **HIPAA**: BAA template for healthcare customers.
- **Employee notice**: provide template language for customer HR/legal teams. Most jurisdictions require disclosure of workplace monitoring; some require consent.
- **Evidentiary standards**: the forensic export must include a tamper-evident chain (hash chain or QLDB), original image, decoded payload, MAC verification proof, and a signed report. Get an external attorney to review the evidence package format for admissibility in your top three customer jurisdictions.

---

## 13. Open Questions

Things to resolve before locking the architecture:

1. **Wayland support timeline.** Many enterprises are still on X11, but the shift is real. Build a wlroots prototype in Phase 5 to inform timing.
2. **Mobile/tablet support.** Insiders increasingly use iPads as auxiliary displays. iOS doesn't allow arbitrary overlays without entitlements — investigate enterprise MDM-deployed app entitlements.
3. **HDR calibration curves.** Each HDR display model needs an empirical Δ-table for imperceptibility at the brightness levels it can reach. Plan a calibration data collection program.
4. **Agent open-sourcing.** Consider open-sourcing the agent (not the backend) for trust-building with security-skeptical customers. Has worked for Tailscale, Sentry, etc.
5. **Anthropic API as a force multiplier.** The extraction pipeline could benefit from Claude vision for de-skewing edge cases, suspicious-photo classification, and natural-language case summaries. Keep the deterministic decode in Rust, layer LLM assistance on top.

---

## Appendix A: Why not just buy / OEM an existing tool?

There are commercial products in adjacent spaces (Digital Guardian, Forcepoint, Code42, Microsoft Purview). None of them do screen watermarking for camera-photo attribution as a core capability. The closest commercial offering is Imatag (mostly for static document watermarking) and a handful of academic/government prototypes. The unique angle — real-time screen overlay + camera-photo decode + enterprise tenancy — is open.

## Appendix B: Reference reading

- Gugelmann, D., Sommer, D., Lenders, V., Happe, M., Vanbever, L. (2018). *Screen Watermarking for Data Theft Investigation and Attribution.* CyCon X.
- Piec, M., Rauber, A. (2014). *Real-time screen watermarking using overlaying layer.* ARES '14.
- Cox, I. et al. (2007). *Digital Watermarking and Steganography.* Morgan Kaufmann.
- Kuhn, M., Anderson, R. (1998). *Soft Tempest: Hidden Data Transmission Using Electromagnetic Emanations.* (For the related "what if you defeated the agent but the screen still leaked" threat surface.)
