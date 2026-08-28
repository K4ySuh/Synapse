# Synapse Test Instructions

- Use `unittest`, public application/repository seams, isolated temporary
  `SYNAPSE_ROOT` state, and fictional `.example`/`.test` assets. Tests must not
  require real targets, credentials, provider accounts, or external traffic.
- Assert negative safety behavior as well as success: scope denial, approval
  required, unavailable dependencies, binding mismatch, stale versions,
  duplicate dispatch prevention, and secret/path non-disclosure.
- Frozen legacy Tier-1 fixtures are byte-exact. Tier-2 normalization is ordered
  and explicit. Regenerate only for an explained intentional contract change;
  never normalize away meaningful drift.
- Keep generated action inventory, output contracts, pack ownership, compact
  payloads, and official-SDK fixtures checked from canonical runtime truth.
- Concurrency tests must use real threads/processes where the guarantee is
  process-level. Prove one claim/dispatch winner, no lost references, durable
  restart reconstruction, and no replay of active or outcome-unknown work.
- Package tests must inspect built wheel and sdist contents, install them in
  isolated targets, resolve every shipped skill reference, and verify the
  package-owned operational prompt outside the checkout.
- Prefer focused execution during development, then `bin/test --core` and the
  applicable modern/phase gate. Report exact test counts and unavailable
  optional environment checks.
