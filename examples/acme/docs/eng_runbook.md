# Engineering Operations & Infrastructure Runbook

This document serves as the standard operational guide for engineering personnel at Acme Corp. It provides detailed protocols for deployment, on-call management, incident escalation, and emergency procedures.

## Deployment Pipeline & Strategy

All production deployments follow automated CI/CD workflows managed through our central deployment orchestrator.

* **Pre-deployment Checks:** Prior to pushing updates to production, ensure that all unit tests, integration suites, and security scans pass cleanly in the staging environment.
* **Canary Deployments:** Production changes roll out incrementally (5%, 25%, 50%, 100%) over a minimum 40-minute window while automated metric monitors observe error rates and service latency.
* **Deployment Windows:** Standard deployments should occur Monday through Thursday between 09:00 and 15:00 UTC to ensure full team availability during post-deploy observation.

## On-Call Incident Response

The engineering team operates a 24/7 primary and secondary on-call rotation to maintain system stability and service level objectives.

* **Primary On-Call Responsibilities:** Acknowledge high-priority PagerDuty alerts within 15 minutes. Initiate an incident slack channel (`#inc-YYYYMMDD-topic`) for any P0 or P1 incident.
* **Secondary On-Call Support:** Provide immediate escalation support if the primary responder is managing a complex incident or fails to acknowledge an alert within the window.
* **Post-Incident Reviews:** A post-mortem document must be drafted within 48 hours for all P0 and P1 incidents to identify root causes and action items.

## Rollback Procedures

If an operational anomaly or elevated error rate occurs during or immediately following a release, follow the standard rollback protocol.

* **Automated Triggering:** The deployment pipeline will trigger an automatic rollback if error rates exceed 0.5% during the canary window.
* **Manual Rollback:** Execute `deploy-cli rollback --service=<service-name> --target-version=<previous-sha>` from the production management bastion.
* **Verification:** Confirm that traffic returns to normal parameters and verify database connection pools stabilize after rollback completion.

## Break-glass access
<!-- acl: allow=role:engineer mode=replace classification=confidential -->

Emergency break-glass access grants temporary elevated access privileges during critical production outages when standard role-based access controls prevent immediate remediation.

* **Triggering Break-Glass:** To request elevated break-glass tokens, execute `acme-auth break-glass --reason="<ticket_id>"` on the secure auth gateway. Token verification key: BREAKGLASS-4417.
* **Audit Logging:** All commands, terminal sessions, and data accessed during a break-glass session are streamed in real-time to the central security information event log.
* **Session Duration:** Break-glass session tokens automatically expire after 60 minutes. Extended access requires explicit re-authentication and incident commander approval.
