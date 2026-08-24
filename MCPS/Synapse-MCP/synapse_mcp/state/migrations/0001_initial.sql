CREATE TABLE store_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    schema_hash TEXT NOT NULL CHECK(length(schema_hash) = 64),
    applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE workspaces (
    workspace_id TEXT PRIMARY KEY,
    organization TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE workspace_revisions (
    workspace_id TEXT PRIMARY KEY REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    revision INTEGER NOT NULL CHECK(revision >= 0),
    updated_at TEXT NOT NULL
);

CREATE TABLE change_log (
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    revision INTEGER NOT NULL CHECK(revision > 0),
    sequence INTEGER NOT NULL CHECK(sequence >= 0),
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    change_kind TEXT NOT NULL CHECK(change_kind IN ('create', 'update', 'delete', 'link')),
    payload_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(payload_json)),
    created_at TEXT NOT NULL,
    PRIMARY KEY (workspace_id, revision, sequence)
);
CREATE INDEX idx_change_log_entity ON change_log(workspace_id, entity_type, entity_id, revision);

CREATE TABLE scope_snapshots (
    scope_snapshot_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    digest TEXT NOT NULL CHECK(length(digest) = 64),
    payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    created_at TEXT NOT NULL,
    UNIQUE (workspace_id, digest),
    UNIQUE (workspace_id, scope_snapshot_id)
);
CREATE INDEX idx_scope_workspace_revision ON scope_snapshots(workspace_id, created_revision);

CREATE TABLE targets (
    target_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    natural_key TEXT NOT NULL,
    kind TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(payload_json)),
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    updated_revision INTEGER NOT NULL CHECK(updated_revision >= created_revision),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (workspace_id, natural_key),
    UNIQUE (workspace_id, target_id)
);
CREATE INDEX idx_targets_workspace_revision ON targets(workspace_id, updated_revision);

CREATE TABLE entities (
    entity_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    target_id TEXT,
    entity_type TEXT NOT NULL,
    natural_key TEXT NOT NULL,
    lifecycle TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(payload_json)),
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    updated_revision INTEGER NOT NULL CHECK(updated_revision >= created_revision),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (workspace_id, entity_type, natural_key),
    UNIQUE (workspace_id, entity_id),
    FOREIGN KEY (workspace_id, target_id) REFERENCES targets(workspace_id, target_id)
);
CREATE INDEX idx_entities_workspace_target ON entities(workspace_id, target_id, entity_type);
CREATE INDEX idx_entities_workspace_revision ON entities(workspace_id, updated_revision);

CREATE TABLE entity_relations (
    relation_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    source_entity_id TEXT NOT NULL,
    target_entity_id TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(payload_json)),
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    created_at TEXT NOT NULL,
    UNIQUE (workspace_id, source_entity_id, target_entity_id, relation_type),
    UNIQUE (workspace_id, relation_id),
    FOREIGN KEY (workspace_id, source_entity_id) REFERENCES entities(workspace_id, entity_id),
    FOREIGN KEY (workspace_id, target_entity_id) REFERENCES entities(workspace_id, entity_id)
);
CREATE INDEX idx_relations_source ON entity_relations(workspace_id, source_entity_id, relation_type);
CREATE INDEX idx_relations_target ON entity_relations(workspace_id, target_entity_id, relation_type);

CREATE TABLE findings (
    finding_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    target_id TEXT,
    natural_key TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    operator_reviewed INTEGER NOT NULL DEFAULT 0 CHECK(operator_reviewed IN (0, 1)),
    payload_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(payload_json)),
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    updated_revision INTEGER NOT NULL CHECK(updated_revision >= created_revision),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (workspace_id, natural_key),
    UNIQUE (workspace_id, finding_id),
    FOREIGN KEY (workspace_id, target_id) REFERENCES targets(workspace_id, target_id)
);
CREATE INDEX idx_findings_workspace_status ON findings(workspace_id, status, updated_revision);

CREATE TABLE review_events (
    review_event_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    finding_id TEXT NOT NULL,
    decision TEXT NOT NULL,
    reviewer_ref TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(payload_json)),
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    created_at TEXT NOT NULL,
    UNIQUE (workspace_id, review_event_id),
    FOREIGN KEY (workspace_id, finding_id) REFERENCES findings(workspace_id, finding_id)
);
CREATE INDEX idx_review_events_finding ON review_events(workspace_id, finding_id, created_revision);

CREATE TABLE evidence (
    evidence_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    target_id TEXT,
    summary TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(payload_json)),
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    created_at TEXT NOT NULL,
    UNIQUE (workspace_id, evidence_id),
    FOREIGN KEY (workspace_id, target_id) REFERENCES targets(workspace_id, target_id)
);
CREATE INDEX idx_evidence_workspace_target ON evidence(workspace_id, target_id, created_revision);

CREATE TABLE actions (
    action_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    action_name TEXT NOT NULL,
    state TEXT NOT NULL,
    plan_fingerprint TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(payload_json)),
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    updated_revision INTEGER NOT NULL CHECK(updated_revision >= created_revision),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (workspace_id, action_id)
);
CREATE INDEX idx_actions_workspace_state ON actions(workspace_id, state, updated_revision);

CREATE TABLE action_dispatches (
    dispatch_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    action_id TEXT NOT NULL,
    authority_grant_id TEXT,
    state TEXT NOT NULL,
    idempotency_key TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(payload_json)),
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    updated_revision INTEGER NOT NULL CHECK(updated_revision >= created_revision),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (workspace_id, dispatch_id),
    FOREIGN KEY (workspace_id, action_id) REFERENCES actions(workspace_id, action_id),
    FOREIGN KEY (workspace_id, authority_grant_id) REFERENCES authority_grants(workspace_id, grant_id)
);
CREATE INDEX idx_dispatches_action ON action_dispatches(workspace_id, action_id, state);

CREATE TABLE artifacts (
    artifact_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    digest TEXT NOT NULL CHECK(length(digest) = 64),
    size INTEGER NOT NULL CHECK(size >= 0),
    media_type TEXT NOT NULL,
    origin TEXT NOT NULL,
    creator_action_id TEXT,
    creator_dispatch_id TEXT,
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    created_at TEXT NOT NULL,
    UNIQUE (workspace_id, digest),
    UNIQUE (workspace_id, artifact_id),
    FOREIGN KEY (workspace_id, creator_action_id) REFERENCES actions(workspace_id, action_id),
    FOREIGN KEY (workspace_id, creator_dispatch_id) REFERENCES action_dispatches(workspace_id, dispatch_id)
);
CREATE INDEX idx_artifacts_workspace_revision ON artifacts(workspace_id, created_revision);

CREATE TABLE evidence_artifacts (
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    evidence_id TEXT NOT NULL,
    artifact_id TEXT NOT NULL,
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    PRIMARY KEY (workspace_id, evidence_id, artifact_id),
    FOREIGN KEY (workspace_id, evidence_id) REFERENCES evidence(workspace_id, evidence_id),
    FOREIGN KEY (workspace_id, artifact_id) REFERENCES artifacts(workspace_id, artifact_id)
);
CREATE INDEX idx_evidence_artifacts_artifact ON evidence_artifacts(workspace_id, artifact_id);

CREATE TABLE tasks (
    task_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    action_id TEXT,
    state TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision > 0),
    payload_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(payload_json)),
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    updated_revision INTEGER NOT NULL CHECK(updated_revision >= created_revision),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (workspace_id, task_id),
    FOREIGN KEY (workspace_id, action_id) REFERENCES actions(workspace_id, action_id)
);
CREATE INDEX idx_tasks_workspace_state ON tasks(workspace_id, state, updated_revision);

CREATE TABLE task_events (
    task_event_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    task_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    task_revision INTEGER NOT NULL CHECK(task_revision > 0),
    payload_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(payload_json)),
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    created_at TEXT NOT NULL,
    UNIQUE (workspace_id, task_event_id),
    FOREIGN KEY (workspace_id, task_id) REFERENCES tasks(workspace_id, task_id)
);
CREATE INDEX idx_task_events_task ON task_events(workspace_id, task_id, task_revision);

CREATE TABLE authority_grants (
    grant_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    current_revision INTEGER NOT NULL CHECK(current_revision > 0),
    state TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    updated_revision INTEGER NOT NULL CHECK(updated_revision >= created_revision),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (workspace_id, grant_id)
);
CREATE INDEX idx_grants_workspace_state ON authority_grants(workspace_id, state, expires_at);

CREATE TABLE authority_grant_revisions (
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    grant_id TEXT NOT NULL,
    grant_revision INTEGER NOT NULL CHECK(grant_revision > 0),
    policy_json TEXT NOT NULL CHECK(json_valid(policy_json)),
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    created_at TEXT NOT NULL,
    PRIMARY KEY (workspace_id, grant_id, grant_revision),
    FOREIGN KEY (workspace_id, grant_id) REFERENCES authority_grants(workspace_id, grant_id)
);

CREATE TABLE step_ups (
    step_up_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    grant_id TEXT NOT NULL,
    grant_revision INTEGER NOT NULL,
    authorization_fingerprint TEXT NOT NULL,
    approved_by_ref TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    created_at TEXT NOT NULL,
    UNIQUE (workspace_id, step_up_id),
    FOREIGN KEY (workspace_id, grant_id, grant_revision)
        REFERENCES authority_grant_revisions(workspace_id, grant_id, grant_revision)
);
CREATE INDEX idx_stepups_grant ON step_ups(workspace_id, grant_id, grant_revision, expires_at);

CREATE TABLE request_states (
    request_state_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    action_id TEXT,
    grant_id TEXT,
    opaque_state_ref TEXT NOT NULL,
    state TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    updated_revision INTEGER NOT NULL CHECK(updated_revision >= created_revision),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (workspace_id, request_state_id),
    FOREIGN KEY (workspace_id, action_id) REFERENCES actions(workspace_id, action_id),
    FOREIGN KEY (workspace_id, grant_id) REFERENCES authority_grants(workspace_id, grant_id)
);
CREATE INDEX idx_request_states_state ON request_states(workspace_id, state, expires_at);

CREATE TABLE budget_windows (
    budget_window_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    grant_id TEXT NOT NULL,
    dimension TEXT NOT NULL,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    reserved INTEGER NOT NULL DEFAULT 0 CHECK(reserved >= 0),
    consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed >= 0),
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    updated_revision INTEGER NOT NULL CHECK(updated_revision >= created_revision),
    UNIQUE (workspace_id, budget_window_id),
    UNIQUE (workspace_id, grant_id, dimension, window_start),
    FOREIGN KEY (workspace_id, grant_id) REFERENCES authority_grants(workspace_id, grant_id)
);

CREATE TABLE reconciliations (
    reconciliation_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    dispatch_id TEXT NOT NULL,
    state TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(payload_json)),
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    created_at TEXT NOT NULL,
    UNIQUE (workspace_id, reconciliation_id),
    FOREIGN KEY (workspace_id, dispatch_id) REFERENCES action_dispatches(workspace_id, dispatch_id)
);
CREATE INDEX idx_reconciliations_dispatch ON reconciliations(workspace_id, dispatch_id);

CREATE TABLE audit_events (
    event_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    revision INTEGER NOT NULL CHECK(revision > 0),
    event_type TEXT NOT NULL,
    summary TEXT NOT NULL,
    actor_ref TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(payload_json)),
    created_at TEXT NOT NULL,
    UNIQUE (workspace_id, event_id)
);
CREATE INDEX idx_audit_workspace_revision ON audit_events(workspace_id, revision, event_id);

CREATE TRIGGER audit_events_no_update
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events_append_only');
END;

CREATE TRIGGER audit_events_no_delete
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events_append_only');
END;

CREATE TABLE migration_runs (
    migration_run_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    source_version TEXT NOT NULL,
    target_version TEXT NOT NULL,
    state TEXT NOT NULL,
    source_manifest_digest TEXT NOT NULL DEFAULT '',
    counts_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(counts_json)),
    started_at TEXT NOT NULL,
    completed_at TEXT
);
CREATE INDEX idx_migration_runs_workspace ON migration_runs(workspace_id, started_at);

CREATE TABLE migration_orphans (
    migration_orphan_id TEXT PRIMARY KEY,
    migration_run_id TEXT NOT NULL REFERENCES migration_runs(migration_run_id) ON DELETE CASCADE,
    source_kind TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(detail_json)),
    UNIQUE (migration_run_id, source_kind, source_ref, reason_code)
);
CREATE INDEX idx_migration_orphans_run ON migration_orphans(migration_run_id, reason_code);

CREATE TABLE id_mappings (
    migration_run_id TEXT NOT NULL REFERENCES migration_runs(migration_run_id) ON DELETE CASCADE,
    source_kind TEXT NOT NULL,
    source_id TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    target_id TEXT NOT NULL,
    PRIMARY KEY (migration_run_id, source_kind, source_id),
    UNIQUE (migration_run_id, target_kind, target_id)
);
