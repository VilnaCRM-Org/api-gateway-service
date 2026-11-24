ALTER TABLE iam_change_receipts
    DROP CONSTRAINT iam_change_receipts_propagation_offset_check,
    DROP CONSTRAINT iam_change_receipts_propagation_status_check,
    DROP COLUMN propagation_offset,
    DROP COLUMN propagation_status;
