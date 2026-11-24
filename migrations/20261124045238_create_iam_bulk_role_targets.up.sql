CREATE TABLE iam_bulk_role_targets (
    operation_id UUID NOT NULL,
    role_id UUID NOT NULL,
    CONSTRAINT iam_bulk_role_targets_pkey PRIMARY KEY (operation_id)
);
