-- 1573238052_create_hawk_credentials.up.sql
CREATE TABLE hawk_credentials(
      id VARCHAR PRIMARY KEY UNIQUE,
      secret bytea NOT NULL,
      validity INTERVAL SECOND(0) DEFAULT INTERVAL '1 minute'
);
