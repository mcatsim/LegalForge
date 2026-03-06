# LexNebulis v1.2 Killer Features Design

**Date**: 2026-03-03
**Status**: Approved
**Author**: CEO + Architecture Review

## Strategic Context

- **Target**: General practice / litigation small firms (2-3 lawyers, 1-2 paralegals, 1 accounting)
- **Goals**: Acquisition hook, daily stickiness, measurable firm revenue impact
- **Primary pain point**: Document chaos
- **AI strategy**: Lightweight pluggable AI layer now (Ollama/cloud), full suite later
- **Mobile strategy**: PWA, not native

---

## 1. Document Intelligence Hub

### 1.1 Smart Document Inbox

Unified ingestion point for all documents entering the firm.

**Input channels**:
- Drag-and-drop upload to matter or general inbox
- Email forwarding (per-matter or general intake address)
- Camera capture (PWA — photograph documents at courthouse)

**Processing pipeline**:
```
Document arrives → OCR (if image/scan) → Text extraction → AI classification → Auto-file or Inbox
```

- **OCR**: Tesseract (self-hosted, Apache 2.0)
- **Text extraction**: pdfplumber (PDF), python-docx (Word)
- **AI classification**: Pluggable service (Ollama local or Claude/OpenAI API)
  - Document type: pleading, contract, correspondence, discovery, invoice, court order
  - Suggested matter (based on party names, case numbers, content similarity)
  - Key dates extracted
  - Key parties/entities mentioned

**AI Safety Architecture — Three-Tier Confidence Model**:

| Tier | Confidence | AI Behavior | Human Action |
|------|-----------|-------------|--------------|
| Auto-file | 95%+ AND same client | File to matter, notify user | None (24h undo) |
| Suggest | 60-95% OR different client | Place in Inbox with suggestion | Approve/correct/reject |
| Manual | <60% OR no match | Place in Inbox, no suggestion | User assigns manually |

**Critical constraint**: Auto-filing ONLY permitted when suggested matter belongs to same client. Cross-client suggestions ALWAYS require human confirmation regardless of confidence.

**Client isolation rules**:
- AI context scoped per-user (only sees matters user has access to)
- Ethical walls enforced — walled matters excluded from suggestion pool
- No cross-client training data in AI prompts
- Case number matching is deterministic (no AI guessing) and handles 60%+ of litigation docs
- Every AI decision logged to immutable audit trail with hash chain

**Misfiling recovery**:
- One-click "Move to correct matter" with audit entry
- Original filing preserved (never deleted)
- Correction recorded: who, when, why
- Optional notification to matter attorneys

**Data model additions**:
- `DocumentMetadata`: extracted_text, document_type, confidence_score, extracted_dates (JSON), extracted_parties (JSON), ocr_status, ai_processed
- `DocumentInbox`: source (upload/email/camera), status (pending/classified/filed/rejected), suggested_matter_id

### 1.2 Full-Text Search with AI Summaries

Search across all document content, not just filenames.

- **Search backend**: PostgreSQL full-text search (tsvector/tsquery) on extracted_text
- **Indexing**: Celery task processes new documents — extract text, generate tsvector
- **AI summaries**: Lazy-generated on first search hit, cached
- **UI**: Rich search results grouped by matter with document type badge, date, relevance, AI summary snippet

### 1.3 Document Timeline

Visual chronological view of all documents in a matter, ordered by date referenced in content (not upload date).

- Uses extracted_dates from AI processing
- Horizontal scrollable timeline with document type icons
- Filterable by document type
- Click to preview/download

### 1.4 Version Comparison

Text-level diff between document versions.

- Uses existing parent_document_id self-referential FK
- DOCX/PDF: extract text, render word-level diff (additions green, deletions red)
- Text-level, not pixel-level — what attorneys need for redlines

---

## 2. Revenue Recovery Features

### 2.1 Automated Payment Reminders

Configurable email escalation for unpaid invoices.

**Default escalation chain** (firm-configurable):

| Trigger | Action | Tone |
|---------|--------|------|
| Invoice issued | Send invoice + payment link | Professional |
| 7 days before due | Friendly reminder | Courteous |
| 1 day past due | Past due notice | Firm |
| 30 days past due | Second notice | Urgent |
| 60 days past due | Final notice | Final |
| 90 days past due | Internal alert only (no client email) | Internal |

**Design decisions**:
- Per-client payment term overrides
- Per-matter pause with logged reason
- Payment link (Stripe/LawPay) included in every reminder
- Firm-customizable templates (uses existing template engine)
- All reminders logged in audit trail

**Data model**:
- `ReminderSchedule`: invoice_id, next_reminder_at, escalation_level, paused, pause_reason, paused_by
- `ReminderLog`: invoice_id, sent_at, escalation_level, recipient_email, template_used, delivery_status

**Backend**: Celery beat daily task queries due reminders, sends emails, advances escalation.

### 2.2 Trust Account Compliance Alerts

Proactive warnings before trust account violations.

**Alert triggers**:

| Alert | Trigger | Action |
|-------|---------|--------|
| Low balance | Client sub-ledger below threshold | Warning to attorney + accounting |
| Overdraw attempt | Disbursement would go negative | **BLOCK transaction** |
| Commingling risk | Operating expense from trust | **BLOCK transaction** |
| Stale funds | Client funds untouched 90+ days | Info to attorney |
| Reconciliation overdue | No reconciliation in 30+ days | Warning to admin + accounting |
| Large transaction | Exceeds configurable threshold | Info to admin |
| Negative balance | Data integrity violation | Critical alert to admin |

**Key design**: Overdraw and commingling are **hard blocks**, not warnings. Per-client sub-ledger awareness — checks client's balance, not just account total.

**Data model**:
- `TrustAlert`: trust_account_id, client_id, alert_type, severity, message, triggered_at, acknowledged_by/at
- `TrustAlertConfig`: trust_account_id, client_id (optional), alert_type, threshold_cents, enabled, notify_emails (JSON)

### 2.3 Plaid Bank Integration (Trust Reconciliation)

Read-only bank data for automated trust account reconciliation.

**PCI-DSS SAQ A compliance**: LexNebulis never touches payment data.

| Data We Store | Storage Method |
|---------------|---------------|
| Plaid access token | Fernet encrypted |
| Plaid item ID | Plaintext (not sensitive) |
| Bank account name | Plaintext |
| Last 4 of account | Plaintext |

| Data We NEVER Store |
|---------------------|
| Full card numbers (PAN) |
| CVV/CVC codes |
| Bank login credentials |
| Full bank account numbers |

**Payment flow**: All payment UI hosted by Stripe/LawPay. Bank credential UI hosted by Plaid Link widget. LexNebulis never sees sensitive payment data.

**Reconciliation flow**:
1. Accounting clicks "Reconcile"
2. Backend calls Plaid accounts/balance/get → real bank balance
3. Compares to LexNebulis ledger total
4. Match → auto-create TrustReconciliation record
5. Mismatch → show discrepancy, pull Plaid transactions for side-by-side review

**Security**:
- Access tokens encrypted at rest
- Tokens scoped to read-only in Plaid dashboard
- Revocable at any time ("Disconnect Bank" button)
- Every Plaid API call logged in audit trail
- Stale token detection with re-auth prompt

### 2.4 LawPay Payment Plans

Installment scheduling for large invoices.

- LawPay API handles recurring charges (no card data on our servers)
- Client receives "Pay $1,500/month for 3 months" option in reminder emails

**Data model**:
- `PaymentPlan`: invoice_id, processor, processor_plan_id, installment_count, installment_amount_cents, frequency, start_date, status
- `PaymentPlanInstallment`: payment_plan_id, installment_number, amount_cents, due_date, status, processor_payment_id, paid_at

---

## 3. Court Rules Engine

### 3.1 Coverage

All 57 US jurisdictions ship on day one:
- Federal (FRCP)
- 50 US States
- District of Columbia
- Puerto Rico, Guam, US Virgin Islands, American Samoa, Northern Mariana Islands

### 3.2 Validation Model — Firm-Owned Responsibility

All rule sets ship as **AI-generated reference rules** with statutory citations. The firm owns validation.

**First-Use Acceptance Gate** (mandatory, cannot be skipped):
- Displayed when firm first uses a jurisdiction's rules
- Only Admin or Attorney can accept (logged in audit trail)
- Per-jurisdiction acceptance (accepting CA does not accept TX)
- Cannot generate deadlines until accepted
- Acceptance includes explicit statement: firm accepts responsibility for validation

**Jurisdiction status tiers**:

| Status | Badge | Can Generate Deadlines? |
|--------|-------|------------------------|
| Not Reviewed | Gray | No |
| Accepted | Yellow "Verify" | Yes, with disclaimer on every deadline |
| Firm Validated | Green checkmark | Yes |
| Customized | Blue | Yes |
| Disabled | Hidden | No |

**Per-rule validation workflow**: Attorney reviews each rule against statute, checks verification box. When all rules checked, jurisdiction moves to "Firm Validated." Full audit trail of who verified what.

### 3.3 Persistent Disclaimers

- **In UI**: Below each generated deadline: "Generated from reference rules. Verify against [CCP §412.20]."
- **In PDF/exports**: Footer with firm responsibility statement
- **In calendar events**: Source citation in description field

### 3.4 Terms of Service Language

Court rules provided "AS IS" without warranty. Firm solely responsible for verification. LexNebulis contributors accept no liability for missed deadlines or incorrect calculations.

### 3.5 Rule Set Content (Per Jurisdiction)

Core deadline chains:
1. Complaint Filed → Answer/Response Due
2. Answer Filed → Scheduling Conference
3. Scheduling Order → Discovery Cutoff
4. Discovery Cutoff → Expert Disclosures / Rebuttal Expert
5. Discovery Cutoff → Dispositive Motion Deadline
6. Trial Date (backward) → Pretrial Conference, Motions in Limine, Exhibit/Witness Lists
7. Service of Process → Response/Waiver

Service method adjustments (personal, mail, electronic — varies by state).
Holiday calendars (federal + state-specific).
Day type handling (calendar, business, court days).
"Mailbox rule" modifiers.
Forward and backward calculation support.

### 3.6 Data Seeding

Rule sets ship as YAML in `alembic/seeds/court_rules/`. Seeded on first run, updated on upgrade.

Community contribution format:
```yaml
jurisdiction: "US-CA"
name: "California Civil Procedure"
source: "California Code of Civil Procedure"
rules:
  - trigger: "complaint_filed"
    name: "Answer or Demurrer Due"
    offset_days: 30
    day_type: "calendar"
    service_adjustments:
      mail: 5
      electronic: 2
    reminder_days: [7, 3, 1]
    description: "CCP §412.20"
```

### 3.7 Maintenance

- Version each rule set with effective_date
- Statutory citation URLs per rule
- Annual review cycle (AI scans for legislative changes, flags for review)
- Community contributions via GitHub PR (citation required)
- Existing matters keep deadlines calculated at creation time

---

## 4. Progressive Web App (PWA)

### 4.1 Core Mobile Use Cases

| Action | Offline Support |
|--------|----------------|
| Check calendar/deadlines | Yes — cache today + 7 days |
| Log time entry | Yes — queue in IndexedDB, sync when online |
| Look up client phone number | Yes — cache contact list |
| Photograph document | Yes — store locally, upload when connected |
| Check matter status | No — online only |

### 4.2 PWA Implementation

- Manifest for home screen install (standalone display)
- Service worker via Workbox
- App shell: cache-first
- Calendar/contacts: stale-while-revalidate
- Time entries + photos: background sync via IndexedDB queue

### 4.3 Offline Time Entry Queue

- Attorney logs time while offline → stored in IndexedDB as "pending_sync"
- Blue banner: "1 time entry will sync when online"
- Background sync fires on reconnection → POST to API
- Success: remove from queue, green notification
- Conflict: keep in queue, show warning

### 4.4 Camera-to-Matter Document Capture

- Uses `<input type="file" capture="environment">` (native camera)
- Photo stored in IndexedDB, queued for upload
- On sync: backend runs OCR → AI classification → normal Document Intelligence pipeline

### 4.5 Responsive Design Changes

- Sidebar → 5-icon bottom navigation on mobile (Dashboard, Matters, Calendar, Time, More)
- DataTable → stacked cards on mobile
- Forms → full-screen modals on mobile
- Timer → floating action button (bottom-right)

### 4.6 Push Notifications (Web Push API)

| Notification | Trigger | Priority |
|-------------|---------|----------|
| Deadline in 24h | Celery beat | High |
| Deadline in 1h | Celery beat | Urgent |
| New portal message | Message webhook | Normal |
| Payment received | Stripe/LawPay webhook | Normal |
| Trust account alert | Alert trigger | High |
| Document filed | AI filing completion | Low |

Permission prompted on first mobile login only.

---

## Technical Dependencies

| Dependency | Purpose | License |
|-----------|---------|---------|
| Tesseract OCR | Image/scan text extraction | Apache 2.0 |
| pdfplumber | PDF text extraction | MIT |
| Workbox | PWA service worker + offline | MIT |
| Plaid SDK | Bank read-only access | Commercial API |
| Ollama (optional) | Self-hosted AI | MIT |

## Security Requirements

- AI context isolation per-user (ethical wall enforcement)
- AI filing audit trail (immutable, hash-chained)
- Three-tier confidence model with cross-client hard block
- Plaid token encryption (Fernet)
- Court rules acceptance gate (attorney-only, audit logged)
- PCI-DSS SAQ A compliance (never touch card data)
- Offline sync conflict resolution
- Push notification permission management

## Prerequisite: Security Remediation

Before implementing these features, the following critical security findings from the architecture review must be fixed:

1. SSO JWT signature verification (CWE-347)
2. SSO state parameter consumption (CWE-352)
3. Encryption salt + key derivation consolidation (CWE-330)
4. Resource-level access control for matters/documents/invoices (CWE-284)
5. Trust account race condition — SELECT FOR UPDATE (CWE-362)
6. Ethical wall enforcement across all endpoints (CWE-284)
7. Rate limiting on 2FA and login (CWE-307)
8. Global exception handler (no stack trace leaks)
9. React ErrorBoundary
10. Token refresh race condition (frontend)

These are documented in the security audit report dated 2026-03-03.
