ALTER TABLE work_items ADD COLUMN dependency_policy TEXT NOT NULL
DEFAULT 'success_required'
CHECK(dependency_policy IN ('success_required', 'terminal_required'));

ALTER TABLE work_items ADD COLUMN blocker_details_json TEXT NOT NULL
DEFAULT '{}'
CHECK(json_valid(blocker_details_json));

CREATE INDEX idx_work_items_dependency_policy
ON work_items(workspace_id, dependency_policy, status, created_workspace_revision);
