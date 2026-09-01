---
name: synapse-perimeter-triage
description: Perform bounded passive-first perimeter, infrastructure, fingerprint, DNS-relation, and OSINT triage for an authorized Synapse target or claimed work item. Use active mapping only through canonical scope and authority.
metadata:
  short-description: Triage authorized perimeter context
  synapse-role: perimeter
  synapse-pack: infra
---

# Triage the Perimeter

Read the shared [operational invariants](../operate-synapse/references/operational-invariants.md)
and follow the [specialist workflow](../operate-synapse/references/specialist-workflow.md).

## Build the passive perimeter first

Start from stored dumps, fingerprints, prior observations, target relations,
and operator notes. Separate observed services and relations from inferred
technology or ownership. Preserve related out-of-scope assets as reviewable
relations without fetching or scanning them.

Use live capability search for fingerprinting, perimeter analysis, network
mapping, and external intelligence behavior. Describe candidate actions before
depending on their traffic, credential, provider, or availability semantics.

## Escalate deliberately

Use approved active probing only to close a concrete version, reachability,
port, or service gap. Keep target set, rate/volume, profile, and output handling
bounded. External intelligence remains third-party data that must be normalized
and corroborated; ordinary DNS resolution alone is not evidence of origin
exposure.

## Handoff

Persist services, versions, relations, evidence, confidence, contradictions,
and coverage gaps. Hand web-facing endpoints to `$synapse-web-assessment`,
versioned components needing vulnerability intelligence to
`$synapse-cve-validation`, and completed coverage to dependent reporting work.
