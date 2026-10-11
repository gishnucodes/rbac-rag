# Internal Audit Findings & Remediation Roadmap

This document outlines the findings, risk ratings, and recommended corrective action plans resulting from the annual internal audit of Acme Corp's operational, financial, and access control systems.

## Executive Summary & Scope

The internal audit team conducted a comprehensive assessment covering financial reporting integrity, identity and access management (IAM) policies, cloud infrastructure security, and vendor risk management.

* **Overall Rating:** Satisfactory with moderate improvements required in identity lifecycle management and third-party vendor review cadence.
* **Audit Tracking Index:** Official audit report registry key AUDIT-3360.
* **Scope Period:** Audit evaluated operations across all corporate business units from October 1 through September 30 of the preceding 12 months.
* **Methodology:** Testing included sample verification of user access requests, automated vulnerability scans, segregation of duties testing in ERP systems, and physical security inspections across operating offices.

## High & Medium Priority Audit Observations

### Finding 1: Privileged Access Review Cadence (Medium Risk)
* **Observation:** User access reviews for corporate cloud infrastructure were conducted bi-annually rather than quarterly as specified in IT Governance policy section 4.2.
* **Impact:** Inactive user credentials or role over-provisioning could persist longer than acceptable under corporate risk tolerance guidelines.
* **Remediation Plan:** Security Operations will implement automated quarterly access review workflows integrated directly with our directory provider by Q1.

### Finding 2: Segregation of Duties in Procurement (Medium Risk)
* **Observation:** Three purchase orders exceeding $50,000 were approved without secondary financial authorization due to legacy workflow rules in the ERP system.
* **Impact:** Increased risk of unapproved expenditure or vendor billing discrepancies.
* **Remediation Plan:** ERP approval workflows have been updated to enforce mandatory dual-approval thresholds for any disbursement above $25,000.

### Finding 3: Vendor Third-Party Risk Assessment Gaps (Low Risk)
* **Observation:** Annual SOC 2 report collection was missing for two SaaS vendors processing non-sensitive operational analytics data.
* **Remediation Plan:** Procurement and Legal will mandate vendor security questionnaire completion prior to annual contract renewals.

## Corrective Action Governance & Reporting

The internal audit committee will track open remediation items on a monthly basis. All high and medium risk findings must achieve full closure within 90 days of final audit report publication. Executive management will receive bi-weekly progress dashboards until all findings are formally re-tested and resolved.
