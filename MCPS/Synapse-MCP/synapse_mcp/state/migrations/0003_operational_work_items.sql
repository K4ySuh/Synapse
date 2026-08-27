CREATE TABLE work_items (
    work_item_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    parent_work_item_id TEXT,
    objective TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK(status IN (
        'planned', 'available', 'claimed', 'running', 'blocked',
        'completed', 'failed', 'cancelled'
    )),
    exclusive_claim INTEGER NOT NULL DEFAULT 1 CHECK(exclusive_claim IN (0, 1)),
    required_packs_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(required_packs_json)),
    selected_packs_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(selected_packs_json)),
    target_selectors_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(target_selectors_json)),
    context_query_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(context_query_json)),
    assignee_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(assignee_json)),
    completion_contract_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(completion_contract_json)),
    progress_summary TEXT NOT NULL DEFAULT '',
    result_summary TEXT NOT NULL DEFAULT '',
    blocker_reason TEXT NOT NULL DEFAULT '',
    handoff_reason TEXT NOT NULL DEFAULT '',
    next_recommended_work TEXT NOT NULL DEFAULT '',
    unresolved_gaps_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(unresolved_gaps_json)),
    version INTEGER NOT NULL CHECK(version > 0),
    created_workspace_revision INTEGER NOT NULL CHECK(created_workspace_revision > 0),
    base_workspace_revision INTEGER NOT NULL CHECK(base_workspace_revision >= 0),
    current_workspace_revision INTEGER NOT NULL CHECK(current_workspace_revision >= created_workspace_revision),
    last_seen_workspace_revision INTEGER NOT NULL CHECK(last_seen_workspace_revision >= 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (workspace_id, work_item_id),
    FOREIGN KEY (workspace_id, parent_work_item_id)
        REFERENCES work_items(workspace_id, work_item_id)
);
CREATE INDEX idx_work_items_workspace_status
ON work_items(workspace_id, status, role, updated_at);
CREATE INDEX idx_work_items_parent
ON work_items(workspace_id, parent_work_item_id, status);

CREATE TABLE work_item_dependencies (
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    work_item_id TEXT NOT NULL,
    depends_on_work_item_id TEXT NOT NULL,
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    PRIMARY KEY (workspace_id, work_item_id, depends_on_work_item_id),
    CHECK(work_item_id <> depends_on_work_item_id),
    FOREIGN KEY (workspace_id, work_item_id)
        REFERENCES work_items(workspace_id, work_item_id) ON DELETE CASCADE,
    FOREIGN KEY (workspace_id, depends_on_work_item_id)
        REFERENCES work_items(workspace_id, work_item_id)
);
CREATE INDEX idx_work_item_dependencies_upstream
ON work_item_dependencies(workspace_id, depends_on_work_item_id, work_item_id);

CREATE TABLE work_item_claims (
    claim_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    work_item_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN (
        'active', 'released', 'handed_off', 'completed', 'expired', 'superseded'
    )),
    principal_ref TEXT NOT NULL CHECK(length(principal_ref) = 71 AND principal_ref LIKE 'sha256:%'),
    authority_session_ref TEXT NOT NULL CHECK(length(authority_session_ref) = 71 AND authority_session_ref LIKE 'sha256:%'),
    agent_run_ref TEXT NOT NULL CHECK(length(agent_run_ref) = 71 AND agent_run_ref LIKE 'sha256:%'),
    worker_label TEXT NOT NULL DEFAULT '',
    claim_revision INTEGER NOT NULL CHECK(claim_revision > 0),
    claim_version INTEGER NOT NULL CHECK(claim_version > 0),
    heartbeat_at TEXT NOT NULL,
    lease_expires_at TEXT NOT NULL,
    released_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (workspace_id, claim_id),
    FOREIGN KEY (workspace_id, work_item_id)
        REFERENCES work_items(workspace_id, work_item_id) ON DELETE CASCADE
);
CREATE INDEX idx_work_item_claims_active
ON work_item_claims(workspace_id, work_item_id, state, lease_expires_at);

CREATE TABLE work_item_references (
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    work_item_id TEXT NOT NULL,
    reference_type TEXT NOT NULL CHECK(reference_type IN (
        'action', 'authority_decision', 'dispatch', 'job', 'evidence',
        'artifact', 'observation', 'candidate', 'finding', 'operation'
    )),
    reference_id TEXT NOT NULL,
    execution_state TEXT NOT NULL DEFAULT '',
    replay_safety TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(payload_json)),
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    updated_revision INTEGER NOT NULL CHECK(updated_revision >= created_revision),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (workspace_id, work_item_id, reference_type, reference_id),
    FOREIGN KEY (workspace_id, work_item_id)
        REFERENCES work_items(workspace_id, work_item_id) ON DELETE CASCADE
);
CREATE INDEX idx_work_item_references_lookup
ON work_item_references(workspace_id, reference_type, reference_id);

CREATE TABLE work_item_events (
    work_item_event_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    work_item_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    work_item_version INTEGER NOT NULL CHECK(work_item_version > 0),
    actor_ref TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(payload_json)),
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    created_at TEXT NOT NULL,
    UNIQUE (workspace_id, work_item_event_id),
    FOREIGN KEY (workspace_id, work_item_id)
        REFERENCES work_items(workspace_id, work_item_id) ON DELETE CASCADE
);
CREATE INDEX idx_work_item_events_item
ON work_item_events(workspace_id, work_item_id, created_revision, work_item_event_id);
