CREATE TABLE work_item_execution_attempts (
    execution_attempt_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    work_item_id TEXT NOT NULL,
    claim_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    idempotency_key_ref TEXT NOT NULL
        CHECK(length(idempotency_key_ref) = 71 AND idempotency_key_ref LIKE 'sha256:%'),
    principal_ref TEXT NOT NULL
        CHECK(length(principal_ref) = 71 AND principal_ref LIKE 'sha256:%'),
    authority_session_ref TEXT NOT NULL
        CHECK(length(authority_session_ref) = 71 AND authority_session_ref LIKE 'sha256:%'),
    agent_run_ref TEXT NOT NULL
        CHECK(length(agent_run_ref) = 71 AND agent_run_ref LIKE 'sha256:%'),
    replay_safety TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL CHECK(state IN (
        'planned', 'started', 'awaiting_approval', 'succeeded',
        'failed', 'denied', 'unknown'
    )),
    outcome_kind TEXT NOT NULL DEFAULT '',
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    updated_revision INTEGER NOT NULL CHECK(updated_revision >= created_revision),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (workspace_id, execution_attempt_id),
    UNIQUE (workspace_id, work_item_id, action_id, idempotency_key_ref),
    FOREIGN KEY (workspace_id, work_item_id)
        REFERENCES work_items(workspace_id, work_item_id) ON DELETE CASCADE,
    FOREIGN KEY (workspace_id, claim_id)
        REFERENCES work_item_claims(workspace_id, claim_id)
);
CREATE INDEX idx_work_execution_attempts_item_state
ON work_item_execution_attempts(workspace_id, work_item_id, state, updated_revision);
