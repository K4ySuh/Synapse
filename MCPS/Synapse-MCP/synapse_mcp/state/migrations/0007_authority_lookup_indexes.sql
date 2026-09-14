-- Ordinary authority reservations resolve only records for the current request.
CREATE INDEX idx_dispatch_idempotency_history
ON action_dispatches(workspace_id, idempotency_key, created_at);

CREATE INDEX idx_dispatch_continuation_job
ON action_dispatches(workspace_id, json_extract(payload_json, '$.continuation.jobId'));

CREATE INDEX idx_request_idempotency
ON authority_runtime_payloads(
    workspace_id, record_kind, json_extract(payload_json, '$.idempotencyKey')
);

CREATE INDEX idx_request_expiry
ON request_states(workspace_id, expires_at);

CREATE INDEX idx_step_up_expiry
ON step_ups(workspace_id, expires_at);
