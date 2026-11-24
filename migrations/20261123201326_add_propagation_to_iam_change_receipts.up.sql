ALTER TABLE iam_change_receipts
    ADD COLUMN propagation_status TEXT,
    ADD COLUMN propagation_offset BIGINT,
    ADD CONSTRAINT iam_change_receipts_propagation_status_check
        CHECK (propagation_status IN ('published', 'committed_pending_propagation')),
    ADD CONSTRAINT iam_change_receipts_propagation_offset_check CHECK (propagation_offset >= 0);
