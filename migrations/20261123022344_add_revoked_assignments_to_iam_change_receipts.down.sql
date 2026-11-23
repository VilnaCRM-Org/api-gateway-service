ALTER TABLE iam_change_receipts
    DROP CONSTRAINT iam_change_receipts_revoked_assignments_check,
    DROP COLUMN revoked_assignments;
