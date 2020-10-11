use crate::{down, up};

up!(r#"
    CREATE TABLE operator_emails (
        id          BIGSERIAL,
        email       TEXT NOT NULL,
        operator_id INTEGER NOT NULL,
        created_at  timestamptz NOT NULL DEFAULT NOW(),
        updated_at  timestamptz NOT NULL DEFAULT NOW()
    );
"#);

down!(
    r#"
    DROP TABLE operator_emails;
    "#
);
