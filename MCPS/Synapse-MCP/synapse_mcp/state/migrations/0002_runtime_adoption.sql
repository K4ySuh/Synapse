CREATE TABLE entity_evidence (
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    entity_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    PRIMARY KEY (workspace_id, entity_id, evidence_id),
    FOREIGN KEY (workspace_id, entity_id) REFERENCES entities(workspace_id, entity_id),
    FOREIGN KEY (workspace_id, evidence_id) REFERENCES evidence(workspace_id, evidence_id)
);
CREATE INDEX idx_entity_evidence_evidence ON entity_evidence(workspace_id, evidence_id, entity_id);

CREATE UNIQUE INDEX uq_dispatch_idempotency
ON action_dispatches(workspace_id, idempotency_key)
WHERE idempotency_key <> '' AND state IN ('authorized', 'dispatched', 'unknown');

CREATE UNIQUE INDEX uq_task_event_revision
ON task_events(workspace_id, task_id, task_revision);

CREATE TABLE task_dispatch_links (
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    task_id TEXT NOT NULL,
    dispatch_id TEXT NOT NULL,
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    PRIMARY KEY (workspace_id, task_id, dispatch_id),
    FOREIGN KEY (workspace_id, task_id) REFERENCES tasks(workspace_id, task_id),
    FOREIGN KEY (workspace_id, dispatch_id) REFERENCES action_dispatches(workspace_id, dispatch_id)
);

CREATE TABLE execution_result_links (
    result_link_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    action_id TEXT NOT NULL,
    dispatch_id TEXT,
    task_id TEXT,
    evidence_id TEXT,
    artifact_id TEXT,
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    created_at TEXT NOT NULL,
    UNIQUE (workspace_id, result_link_id),
    FOREIGN KEY (workspace_id, action_id) REFERENCES actions(workspace_id, action_id),
    FOREIGN KEY (workspace_id, dispatch_id) REFERENCES action_dispatches(workspace_id, dispatch_id),
    FOREIGN KEY (workspace_id, task_id) REFERENCES tasks(workspace_id, task_id),
    FOREIGN KEY (workspace_id, evidence_id) REFERENCES evidence(workspace_id, evidence_id),
    FOREIGN KEY (workspace_id, artifact_id) REFERENCES artifacts(workspace_id, artifact_id)
);
CREATE INDEX idx_result_links_dispatch ON execution_result_links(workspace_id, dispatch_id, created_revision);

CREATE TABLE authority_runtime_payloads (
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    record_kind TEXT NOT NULL CHECK(record_kind IN ('request_state', 'step_up', 'budget_window')),
    record_id TEXT NOT NULL,
    payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
    updated_revision INTEGER NOT NULL CHECK(updated_revision > 0),
    PRIMARY KEY (workspace_id, record_kind, record_id)
);

CREATE TABLE authority_repository_revisions (
    workspace_id TEXT PRIMARY KEY REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    revision INTEGER NOT NULL CHECK(revision >= 0),
    updated_at TEXT NOT NULL
);

CREATE TABLE authority_decisions (
    decision_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    created_at TEXT NOT NULL,
    UNIQUE (workspace_id, decision_id)
);
CREATE INDEX idx_authority_decisions_revision
ON authority_decisions(workspace_id, created_revision, decision_id);

CREATE TABLE artifact_resource_refs (
    reference_digest TEXT PRIMARY KEY CHECK(length(reference_digest) = 71 AND reference_digest LIKE 'sha256:%'),
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    artifact_id TEXT NOT NULL,
    principal_ref TEXT NOT NULL CHECK(length(principal_ref) = 71 AND principal_ref LIKE 'sha256:%'),
    authority_session_ref TEXT NOT NULL CHECK(length(authority_session_ref) = 71 AND authority_session_ref LIKE 'sha256:%'),
    artifact_type TEXT NOT NULL,
    media_type TEXT NOT NULL,
    version TEXT NOT NULL CHECK(length(version) = 64),
    size INTEGER NOT NULL CHECK(size >= 0),
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    created_at TEXT NOT NULL,
    UNIQUE (workspace_id, reference_digest),
    FOREIGN KEY (workspace_id, artifact_id) REFERENCES artifacts(workspace_id, artifact_id)
);
CREATE INDEX idx_resource_refs_artifact
ON artifact_resource_refs(workspace_id, artifact_id);

CREATE TABLE checkpoint_leases (
    workspace_id TEXT PRIMARY KEY REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    owner_ref TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('running', 'completed', 'blocked', 'failed')),
    started_at TEXT NOT NULL,
    completed_at TEXT,
    detail_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(detail_json))
);
