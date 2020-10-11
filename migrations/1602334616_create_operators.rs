use crate::{down, up};

up!(r#"
    CREATE TABLE operators (
        id         BIGSERIAL,
        name       TEXT NOT NULL UNIQUE,
        created_at timestamptz NOT NULL DEFAULT NOW(),
        updated_at timestamptz NOT NULL DEFAULT NOW()
    );
"#);

down!(
    r#"
    DROP TABLE operators;
    "#
);
