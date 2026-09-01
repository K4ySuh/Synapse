---
name: synapse-web-assessment
description: Assess an authorized web application's observed routes, JavaScript, authentication boundaries, and vulnerability candidates through Synapse. Use passive evidence first and reserve active validation for covered, candidate-specific actions.
metadata:
  short-description: Assess authorized web application context
  synapse-role: web
  synapse-pack: web
---

# Assess a Web Application

Read the shared [operational invariants](../operate-synapse/references/operational-invariants.md)
and follow the [specialist workflow](../operate-synapse/references/specialist-workflow.md).

## Model the observed application

Begin with stored requests, dumps, sitemap data, response behavior, scripts,
forms, routes, parameters, fingerprints, and prior evidence. Keep observed
traffic distinct from routes inferred from static JavaScript or specifications.
Record cross-host discoveries without fetching assets outside scope.

Describe the authentication flow before authenticated work, especially for
SSO, MFA, CAPTCHA, dynamic tokens, or manual approval. Use credential/profile
references only after the applicable operator-controlled storage and execution
gate.

## Triage candidates

Use live capability search to select passive analyzers appropriate to the
observed request shape and technology. Preserve methods, headers, bodies,
cookies, identifiers, and source references. A scanner label or heuristic
signal is a candidate, not a finding.

Plan active validation around one concrete candidate and benign expected
effect. Explain exact target, request context, traffic/state effect, scope, and
authority before execution. Never broaden a validation into destructive
exploitation or silently replace authenticated behavior with anonymous tests.

## Handoff

Persist routes, app-model relations, candidates, evidence, negative results,
authentication gaps, and remaining uncertainty. Hand actor/object authorization
questions to `$synapse-access-control`, versioned component questions to
`$synapse-cve-validation`, and completed coverage to reporting dependencies.
