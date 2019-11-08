-- 1573238043_create_signers.up.sql

-- stores IDs until we can move additional signer config to the DB
CREATE TABLE signers(
      id VARCHAR PRIMARY KEY UNIQUE NOT NULL
);
