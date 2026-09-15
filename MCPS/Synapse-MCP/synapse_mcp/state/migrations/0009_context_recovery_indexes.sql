CREATE INDEX idx_execution_runs_authority_recovery
ON execution_runs(
    workspace_id,
    json_extract(payload_json, '$.authorizationBinding.authoritySessionRef'),
    state,
    updated_revision DESC,
    execution_run_id
);
