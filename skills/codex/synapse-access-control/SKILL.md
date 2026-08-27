---
name: synapse-access-control
description: Model and validate authorized object-, function-, and property-level access control in Synapse. Use when at least one actor, protected object or function, and expected allow/deny behavior can be grounded.
metadata:
  short-description: Model authorized access-control behavior
  synapse-role: access-control
  synapse-pack: web
---

# Assess Access Control

Read the shared [operational invariants](../operate-synapse/references/operational-invariants.md)
and follow the [specialist workflow](../operate-synapse/references/specialist-workflow.md).

## Establish the model

Identify object types and identifier shapes without storing raw object IDs by
default. Record actor contexts with role, auth state, approved credential
reference, owned object types, and expected access. Preserve function and
property boundaries as well as object ownership.

Prefer one known-allowed baseline and one expected-denied comparison. Treat a
redirect to login as denial or an authentication boundary, not successful
access. Ask for the operator's auth-flow description before automating complex
SSO, MFA, CAPTCHA, or dynamic-token behavior.

## Plan and validate

Build a bounded test matrix from observed requests and explicit expectations.
Review request context, identities, likely state effects, scope, and authority
before any replay. Do not downgrade an authenticated comparison to anonymous
execution unless the operator chose that behavior.

Record expected versus observed outcomes conservatively. Promote a broken
access-control candidate only after the affected asset, actor comparison,
impact, and evidence are reviewed.

## Handoff

Complete with covered actor/object/function/property combinations, evidence,
confirmed denials, candidates, contradictions, authentication gaps, and the
next comparison needed. Block rather than guess when a baseline identity,
approved auth state, scope, or execution authority is missing.
