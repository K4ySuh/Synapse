CREATE TABLE execution_runs (
    execution_run_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    dispatch_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    intent_version INTEGER NOT NULL CHECK(intent_version > 0),
    intent_fingerprint TEXT NOT NULL CHECK(length(intent_fingerprint) = 64),
    plan_version INTEGER NOT NULL CHECK(plan_version > 0),
    plan_fingerprint TEXT NOT NULL CHECK(length(plan_fingerprint) = 64),
    authorization_fingerprint TEXT NOT NULL CHECK(length(authorization_fingerprint) = 64),
    authorization_binding_fingerprint TEXT NOT NULL CHECK(length(authorization_binding_fingerprint) = 64),
    idempotency_key_ref TEXT NOT NULL
        CHECK(length(idempotency_key_ref) = 71 AND idempotency_key_ref LIKE 'sha256:%'),
    work_item_id TEXT,
    work_execution_attempt_id TEXT,
    parent_execution_run_id TEXT,
    job_id TEXT,
    state TEXT NOT NULL CHECK(state IN (
        'authorized', 'dispatch_started', 'observing', 'validation_pending',
        'outcome_committed', 'execution_unknown', 'not_dispatched'
    )),
    outcome_kind TEXT NOT NULL DEFAULT '',
    observation_coverage_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(observation_coverage_json)),
    final_validation_id TEXT,
    payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    updated_revision INTEGER NOT NULL CHECK(updated_revision >= created_revision),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (workspace_id, execution_run_id),
    UNIQUE (workspace_id, dispatch_id),
    FOREIGN KEY (workspace_id, dispatch_id)
        REFERENCES action_dispatches(workspace_id, dispatch_id),
    FOREIGN KEY (workspace_id, action_id)
        REFERENCES actions(workspace_id, action_id),
    FOREIGN KEY (workspace_id, work_item_id)
        REFERENCES work_items(workspace_id, work_item_id),
    FOREIGN KEY (workspace_id, work_execution_attempt_id)
        REFERENCES work_item_execution_attempts(workspace_id, execution_attempt_id),
    FOREIGN KEY (workspace_id, parent_execution_run_id)
        REFERENCES execution_runs(workspace_id, execution_run_id)
        DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX idx_execution_runs_state
ON execution_runs(workspace_id, state, updated_revision, execution_run_id);
CREATE INDEX idx_execution_runs_work_attempt
ON execution_runs(workspace_id, work_execution_attempt_id, updated_revision);
CREATE INDEX idx_execution_runs_job
ON execution_runs(workspace_id, job_id, updated_revision);

CREATE TABLE execution_observations (
    observation_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    execution_run_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK(sequence > 0),
    trust_class TEXT NOT NULL CHECK(trust_class IN (
        'runtime_observed', 'runtime_enforced', 'provider_reported',
        'consumer_reported', 'model_reported', 'legacy_unknown'
    )),
    effect_class TEXT NOT NULL,
    observation_fingerprint TEXT NOT NULL CHECK(length(observation_fingerprint) = 64),
    payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    created_at TEXT NOT NULL,
    UNIQUE (workspace_id, observation_id),
    UNIQUE (workspace_id, execution_run_id, sequence),
    UNIQUE (workspace_id, execution_run_id, observation_fingerprint),
    FOREIGN KEY (workspace_id, execution_run_id)
        REFERENCES execution_runs(workspace_id, execution_run_id) ON DELETE CASCADE
);
CREATE INDEX idx_execution_observations_run
ON execution_observations(workspace_id, execution_run_id, sequence);

CREATE TABLE effect_validations (
    validation_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    execution_run_id TEXT NOT NULL,
    verdict TEXT NOT NULL CHECK(verdict IN (
        'not_dispatched', 'within_envelope', 'outside_envelope',
        'incomplete', 'unobservable', 'indeterminate'
    )),
    validation_fingerprint TEXT NOT NULL CHECK(length(validation_fingerprint) = 64),
    payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    created_at TEXT NOT NULL,
    UNIQUE (workspace_id, validation_id),
    UNIQUE (workspace_id, execution_run_id, validation_fingerprint),
    FOREIGN KEY (workspace_id, execution_run_id)
        REFERENCES execution_runs(workspace_id, execution_run_id) ON DELETE CASCADE
);
CREATE INDEX idx_effect_validations_run
ON effect_validations(workspace_id, execution_run_id, created_revision, validation_id);
