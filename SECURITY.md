# Security Policy

Synapse is intended for authorized security testing and defensive assessment
workflows. Security reports, examples, and reproduction notes must avoid
including real secrets, reusable credentials, customer data, or engagement
details that are not cleared for disclosure.

## Supported Versions

This repository currently tracks active development on the main branch. Until
formal releases are cut, security fixes are applied to the current development
tree.

## Reporting A Vulnerability

Use the repository's private vulnerability reporting channel when available. If
no private channel is configured, contact the maintainer through the
maintainer-designated private channel for the project. If only public issue
tracking is available, open a minimal issue that says a private security report
is needed and do not include exploit details, secrets, target names, or
reproduction payloads.

Include enough non-sensitive context to triage the issue:

- affected component or file path,
- impact and expected security boundary,
- sanitized reproduction steps,
- observed and expected behavior,
- whether the issue can send traffic, mutate state, expose secrets, or bypass
  scope/confirmation gates.

## Security Boundaries

Reports are especially useful when they affect:

- scope enforcement or confirmation gates,
- credential redaction or secret storage,
- active traffic controls,
- evidence sanitization,
- workspace or dump data isolation,
- Shodan API key handling,
- SQLMap, ffuf, Nuclei, nmap, crawler, or replay guardrails.

Do not use Synapse to test systems without authorization while preparing a
report.
