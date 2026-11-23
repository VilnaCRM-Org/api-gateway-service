ALTER TABLE iam_change_receipts
    ADD COLUMN revoked_assignments INTEGER,
    ADD CONSTRAINT iam_change_receipts_revoked_assignments_check CHECK (revoked_assignments >= 0);
