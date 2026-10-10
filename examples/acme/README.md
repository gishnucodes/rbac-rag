# Acme Corp Example Corpus & Expected Access Ground Truth

This directory contains the example corpus for Acme Corp, including documents, section ACL directives, identity directory, ingestion manifest, and policy versions `v1` and `v2`.

---

## Directory & Persona Overview

| User ID | Display Name | Groups | Direct Roles | Resolved Effective Roles (v1) | Clearance (v1) | Resolved Effective Roles (v2) | Clearance (v2) |
|---|---|---|---|---|---|---|---|
| `alice` | Alice | `engineering` | *None* | `engineer`, `employee` | 1 | `engineer`, `employee` | 1 |
| `bob` | Bob | `hr` | *None* | `hr_manager`, `employee` | 2 | `hr_manager`, `employee` | 2 |
| `carol` | Carol (CFO) | `finance`, `executives` | *None* | `finance_analyst`, `executive`, `employee` | 3 | `finance_analyst`, `auditor`, `executive`, `employee` | 3 |
| `dave` | Dave | `interns` | *None* | `intern` | 0 | `intern`, `employee` | 1 |
| `erin` | Erin | `contractors` | *None* | `contractor` | 1 | `contractor` | 1 |
| `frank` | Frank | `finance` | *None* | `finance_analyst`, `employee` | 2 | `finance_analyst`, `auditor`, `employee` | 2 |
| `grace` | Grace | `legal` | `general_counsel` | `general_counsel` | 3 | `general_counsel` | 3 |
| `henry` | Henry (CEO) | `executives` | *None* | `executive`, `employee` | 3 | `executive`, `employee` | 3 |
| `mallory` | Mallory | *Absent* | *None* | *None* (Unknown user) | 0 | *None* (Unknown user) | 0 |

---

## Document Corpus & Section Directives

1. **`handbook.md`** (`public`, clearance required: 0)
   - Allow: `role:employee`, `role:intern`, `role:contractor`
   - Deny: None
2. **`eng_runbook.md`** (`internal`, clearance required: 1)
   - Allow: `role:engineer`, `role:contractor`, `role:intern`
   - Deny: None
   - **Section `Break-glass access`** (`confidential`, clearance required: 2): `<!-- acl: allow=role:engineer mode=replace classification=confidential -->`
3. **`hr_comp_bands.md`** (`confidential`, clearance required: 2)
   - Allow: `role:hr_manager`, `role:executive`
   - Deny: None
4. **`finance_q3.md`** (`confidential`, clearance required: 2)
   - Allow: `role:finance_analyst`, `role:executive`
   - Deny: None
   - **Section `Acquisition reserve`** (`restricted`, clearance required: 3): `<!-- acl: allow=role:executive mode=replace classification=restricted -->`
5. **`legal_project_nightjar.md`** (`restricted`, clearance required: 3)
   - Allow: `role:executive`, `user:grace`
   - Deny: `user:carol` (explicit recusal)
6. **`audit_findings.md`** (`confidential`, clearance required: 2)
   - Allow: `role:auditor`, `role:executive`
   - Deny: None

---

## Ground Truth Expected Access Matrix

| Persona | Document / Section | Classification | v1 Access | v1 Reason | v2 Access | v2 Reason |
|---|---|---|---|---|---|---|
| **`alice`** | `handbook.md` | `public` | **ALLOW** | Allowed via `role:employee` (clearance 1 >= 0) | **ALLOW** | Allowed via `role:employee` (clearance 1 >= 0) |
| | `eng_runbook.md` (Main) | `internal` | **ALLOW** | Allowed via `role:engineer` (clearance 1 >= 1) | **ALLOW** | Allowed via `role:engineer` (clearance 1 >= 1) |
| | `eng_runbook.md` (`Break-glass access`) | `confidential` | **DENY** | Insufficient clearance (clearance 1 < 2) | **DENY** | Insufficient clearance (clearance 1 < 2) |
| | `hr_comp_bands.md` | `confidential` | **DENY** | Insufficient clearance (clearance 1 < 2) | **DENY** | Insufficient clearance (clearance 1 < 2) |
| | `finance_q3.md` (Main) | `confidential` | **DENY** | Insufficient clearance (clearance 1 < 2) | **DENY** | Insufficient clearance (clearance 1 < 2) |
| | `finance_q3.md` (`Acquisition reserve`) | `restricted` | **DENY** | Insufficient clearance (clearance 1 < 3) | **DENY** | Insufficient clearance (clearance 1 < 3) |
| | `legal_project_nightjar.md` | `restricted` | **DENY** | Insufficient clearance (clearance 1 < 3) | **DENY** | Insufficient clearance (clearance 1 < 3) |
| | `audit_findings.md` | `confidential` | **DENY** | Insufficient clearance (clearance 1 < 2) | **DENY** | Insufficient clearance (clearance 1 < 2) |
| **`bob`** | `handbook.md` | `public` | **ALLOW** | Allowed via `role:employee` (clearance 2 >= 0) | **ALLOW** | Allowed via `role:employee` (clearance 2 >= 0) |
| | `eng_runbook.md` (Main) | `internal` | **DENY** | No matching allow principal | **DENY** | No matching allow principal |
| | `eng_runbook.md` (`Break-glass access`) | `confidential` | **DENY** | No matching allow principal | **DENY** | No matching allow principal |
| | `hr_comp_bands.md` | `confidential` | **ALLOW** | Allowed via `role:hr_manager` (clearance 2 >= 2) | **ALLOW** | Allowed via `role:hr_manager` (clearance 2 >= 2) |
| | `finance_q3.md` (Main) | `confidential` | **DENY** | No matching allow principal | **DENY** | No matching allow principal |
| | `finance_q3.md` (`Acquisition reserve`) | `restricted` | **DENY** | Insufficient clearance (clearance 2 < 3) | **DENY** | Insufficient clearance (clearance 2 < 3) |
| | `legal_project_nightjar.md` | `restricted` | **DENY** | Insufficient clearance (clearance 2 < 3) | **DENY** | Insufficient clearance (clearance 2 < 3) |
| | `audit_findings.md` | `confidential` | **DENY** | No matching allow principal | **DENY** | No matching allow principal |
| **`carol`** | `handbook.md` | `public` | **ALLOW** | Allowed via `role:employee` (clearance 3 >= 0) | **ALLOW** | Allowed via `role:employee` (clearance 3 >= 0) |
| | `eng_runbook.md` (Main) | `internal` | **DENY** | No matching allow principal | **DENY** | No matching allow principal |
| | `eng_runbook.md` (`Break-glass access`) | `confidential` | **DENY** | No matching allow principal | **DENY** | No matching allow principal |
| | `hr_comp_bands.md` | `confidential` | **ALLOW** | Allowed via `role:executive` (clearance 3 >= 2) | **ALLOW** | Allowed via `role:executive` (clearance 3 >= 2) |
| | `finance_q3.md` (Main) | `confidential` | **ALLOW** | Allowed via `role:finance_analyst` / `role:executive` | **ALLOW** | Allowed via `role:finance_analyst` / `role:executive` |
| | `finance_q3.md` (`Acquisition reserve`) | `restricted` | **ALLOW** | Allowed via `role:executive` (clearance 3 >= 3) | **ALLOW** | Allowed via `role:executive` (clearance 3 >= 3) |
| | `legal_project_nightjar.md` | `restricted` | **DENY** | Explicit deny for `user:carol` (recusal overrides allow) | **DENY** | Explicit deny for `user:carol` (recusal overrides allow) |
| | `audit_findings.md` | `confidential` | **ALLOW** | Allowed via `role:executive` (clearance 3 >= 2) | **ALLOW** | Allowed via `role:executive` (clearance 3 >= 2) |
| **`dave`** | `handbook.md` | `public` | **ALLOW** | Allowed via `role:intern` (clearance 0 >= 0) | **ALLOW** | Allowed via `role:intern` (clearance 1 >= 0) |
| | `eng_runbook.md` (Main) | `internal` | **DENY** | Insufficient clearance in v1 (clearance 0 < 1) | **ALLOW** | Allowed via `role:intern` in v2 (clearance 1 >= 1) |
| | `eng_runbook.md` (`Break-glass access`) | `confidential` | **DENY** | Insufficient clearance (clearance 0 < 2) | **DENY** | Insufficient clearance (clearance 1 < 2) |
| | `hr_comp_bands.md` | `confidential` | **DENY** | Insufficient clearance (clearance 0 < 2) | **DENY** | Insufficient clearance (clearance 1 < 2) |
| | `finance_q3.md` (Main) | `confidential` | **DENY** | Insufficient clearance (clearance 0 < 2) | **DENY** | Insufficient clearance (clearance 1 < 2) |
| | `finance_q3.md` (`Acquisition reserve`) | `restricted` | **DENY** | Insufficient clearance (clearance 0 < 3) | **DENY** | Insufficient clearance (clearance 1 < 3) |
| | `legal_project_nightjar.md` | `restricted` | **DENY** | Insufficient clearance (clearance 0 < 3) | **DENY** | Insufficient clearance (clearance 1 < 3) |
| | `audit_findings.md` | `confidential` | **DENY** | Insufficient clearance (clearance 0 < 2) | **DENY** | Insufficient clearance (clearance 1 < 2) |
| **`erin`** | `handbook.md` | `public` | **ALLOW** | Allowed via `role:contractor` (clearance 1 >= 0) | **ALLOW** | Allowed via `role:contractor` (clearance 1 >= 0) |
| | `eng_runbook.md` (Main) | `internal` | **ALLOW** | Allowed via `role:contractor` in v1 (clearance 1 >= 1) | **DENY** | Policy deny rule for `group:contractors` on `internal` |
| | `eng_runbook.md` (`Break-glass access`) | `confidential` | **DENY** | Insufficient clearance & policy deny rule | **DENY** | Insufficient clearance & policy deny rule |
| | `hr_comp_bands.md` | `confidential` | **DENY** | Insufficient clearance & policy deny rule | **DENY** | Insufficient clearance & policy deny rule |
| | `finance_q3.md` (Main) | `confidential` | **DENY** | Insufficient clearance & policy deny rule | **DENY** | Insufficient clearance & policy deny rule |
| | `finance_q3.md` (`Acquisition reserve`) | `restricted` | **DENY** | Insufficient clearance & policy deny rule | **DENY** | Insufficient clearance & policy deny rule |
| | `legal_project_nightjar.md` | `restricted` | **DENY** | Insufficient clearance (clearance 1 < 3) | **DENY** | Insufficient clearance (clearance 1 < 3) |
| | `audit_findings.md` | `confidential` | **DENY** | Insufficient clearance & policy deny rule | **DENY** | Insufficient clearance & policy deny rule |
| **`frank`**| `handbook.md` | `public` | **ALLOW** | Allowed via `role:employee` (clearance 2 >= 0) | **ALLOW** | Allowed via `role:employee` (clearance 2 >= 0) |
| | `eng_runbook.md` (Main) | `internal` | **DENY** | No matching allow principal | **DENY** | No matching allow principal |
| | `eng_runbook.md` (`Break-glass access`) | `confidential` | **DENY** | No matching allow principal | **DENY** | No matching allow principal |
| | `hr_comp_bands.md` | `confidential` | **DENY** | No matching allow principal | **DENY** | No matching allow principal |
| | `finance_q3.md` (Main) | `confidential` | **ALLOW** | Allowed via `role:finance_analyst` (clearance 2 >= 2) | **ALLOW** | Allowed via `role:finance_analyst` (clearance 2 >= 2) |
| | `finance_q3.md` (`Acquisition reserve`) | `restricted` | **DENY** | Insufficient clearance (clearance 2 < 3) | **DENY** | Insufficient clearance (clearance 2 < 3) |
| | `legal_project_nightjar.md` | `restricted` | **DENY** | Insufficient clearance (clearance 2 < 3) | **DENY** | Insufficient clearance (clearance 2 < 3) |
| | `audit_findings.md` | `confidential` | **DENY** | No matching allow principal in v1 (finance has no auditor) | **ALLOW** | Allowed via `role:auditor` in v2 (finance maps to auditor) |
| **`grace`**| `handbook.md` | `public` | **DENY** | No matching allow principal (legal group maps to general_counsel) | **DENY** | No matching allow principal |
| | `eng_runbook.md` (Main) | `internal` | **DENY** | No matching allow principal | **DENY** | No matching allow principal |
| | `eng_runbook.md` (`Break-glass access`) | `confidential` | **DENY** | No matching allow principal | **DENY** | No matching allow principal |
| | `hr_comp_bands.md` | `confidential` | **DENY** | No matching allow principal | **DENY** | No matching allow principal |
| | `finance_q3.md` (Main) | `confidential` | **DENY** | No matching allow principal | **DENY** | No matching allow principal |
| | `finance_q3.md` (`Acquisition reserve`) | `restricted` | **DENY** | No matching allow principal | **DENY** | No matching allow principal |
| | `legal_project_nightjar.md` | `restricted` | **ALLOW** | Allowed via explicit user match `user:grace` (clearance 3 >= 3) | **ALLOW** | Allowed via explicit user match `user:grace` (clearance 3 >= 3) |
| | `audit_findings.md` | `confidential` | **DENY** | No matching allow principal | **DENY** | No matching allow principal |
| **`henry`**| `handbook.md` | `public` | **ALLOW** | Allowed via `role:employee` (clearance 3 >= 0) | **ALLOW** | Allowed via `role:employee` (clearance 3 >= 0) |
| | `eng_runbook.md` (Main) | `internal` | **DENY** | No matching allow principal | **DENY** | No matching allow principal |
| | `eng_runbook.md` (`Break-glass access`) | `confidential` | **DENY** | No matching allow principal | **DENY** | No matching allow principal |
| | `hr_comp_bands.md` | `confidential` | **ALLOW** | Allowed via `role:executive` (clearance 3 >= 2) | **ALLOW** | Allowed via `role:executive` (clearance 3 >= 2) |
| | `finance_q3.md` (Main) | `confidential` | **ALLOW** | Allowed via `role:executive` (clearance 3 >= 2) | **ALLOW** | Allowed via `role:executive` (clearance 3 >= 2) |
| | `finance_q3.md` (`Acquisition reserve`) | `restricted` | **ALLOW** | Allowed via `role:executive` (clearance 3 >= 3) | **ALLOW** | Allowed via `role:executive` (clearance 3 >= 3) |
| | `legal_project_nightjar.md` | `restricted` | **ALLOW** | Allowed via `role:executive` (clearance 3 >= 3) | **ALLOW** | Allowed via `role:executive` (clearance 3 >= 3) |
| | `audit_findings.md` | `confidential` | **ALLOW** | Allowed via `role:executive` (clearance 3 >= 2) | **ALLOW** | Allowed via `role:executive` (clearance 3 >= 2) |
| **`mallory`**| All Documents & Sections | Any | **DENY** | Unknown user (subject unresolved) | **DENY** | Unknown user (subject unresolved) |

---

## Explanation of Key Access Transitions (v1 -> v2)

1. **Dave (`dave`) — Intern Clearance Elevation:**
   - Under **v1**, `intern` has clearance `0` and does not inherit `employee`. Dave cannot access `eng_runbook.md` (`internal`, clearance 1).
   - Under **v2**, `intern` clearance increases to `1` and inherits `employee`. Dave gains access to `eng_runbook.md` (main document).
2. **Erin (`erin`) — Contractor Internal Restriction:**
   - Under **v1**, `group:contractors` is denied `confidential` documents. Erin can access `eng_runbook.md` (`internal`).
   - Under **v2**, `policy_v2.yaml` adds a policy deny rule for `group:contractors` on `internal`. Erin is denied access to `eng_runbook.md`.
3. **Frank (`frank`) — Finance Group Mapping Expansion:**
   - Under **v1**, `finance` group maps only to `finance_analyst`. Frank cannot access `audit_findings.md` (requires `role:auditor` or `role:executive`).
   - Under **v2**, `finance` group maps to `[finance_analyst, auditor]`. Frank gains effective role `auditor` (clearance 2) and can now access `audit_findings.md`.
