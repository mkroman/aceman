use crate::{down, up};

up!(r#"
    CREATE TABLE operator_logs (
        id BIGSERIAL,
        description TEXT,
        key TEXT NOT NULL,
        log_id TEXT NOT NULL,
        url TEXT NOT NULL,
        mmd INTEGER NOT NULL,
        dns TEXT,
        log_type TEXT,
        operator_id INTEGER NOT NULL,
        state TEXT,
        state_time timestamptz NOT NULL,
        created_at timestamptz NOT NULL DEFAULT NOW(),
        updated_at timestamptz NOT NULL DEFAULT NOW()
    );
"#);

down!(
    r#"
    DROP TABLE operator_logs;
    "#
);
