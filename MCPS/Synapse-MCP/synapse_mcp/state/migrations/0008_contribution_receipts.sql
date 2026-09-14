CREATE TABLE contribution_receipts (
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    principal_ref TEXT NOT NULL CHECK(length(principal_ref) = 71 AND principal_ref LIKE 'sha256:%'),
    request_id TEXT NOT NULL,
    payload_fingerprint TEXT NOT NULL CHECK(length(payload_fingerprint) = 64),
    receipt_json TEXT NOT NULL CHECK(json_valid(receipt_json)),
    created_revision INTEGER NOT NULL CHECK(created_revision > 0),
    created_at TEXT NOT NULL,
    PRIMARY KEY (workspace_id, principal_ref, request_id)
);
CREATE INDEX idx_contribution_receipts_revision
ON contribution_receipts(workspace_id, created_revision);
