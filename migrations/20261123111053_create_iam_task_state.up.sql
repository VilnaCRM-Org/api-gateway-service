CREATE TABLE iam_task_state (
    task_name TEXT NOT NULL,
    last_run_at TIMESTAMPTZ NOT NULL,
    run_count BIGINT NOT NULL,
    CONSTRAINT iam_task_state_pkey PRIMARY KEY (task_name),
    CONSTRAINT iam_task_state_task_name_check CHECK (char_length(task_name) BETWEEN 1 AND 100),
    CONSTRAINT iam_task_state_run_count_check CHECK (run_count >= 1)
);
