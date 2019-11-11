-- 1573238040_init.up.sql

CREATE ROLE myautographdbuser;
ALTER ROLE myautographdbuser WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB LOGIN PASSWORD 'myautographdbpassword';

CREATE TABLE endentities(
      id          SERIAL PRIMARY KEY,
      label       VARCHAR NOT NULL,
      hsm_handle  BIGINT NOT NULL,
      signer_id   VARCHAR NOT NULL,
      is_current  BOOLEAN NOT NULL,
      x5u         VARCHAR NULL,
      created_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX endentities_latest_idx ON endentities(label, signer_id, is_current);
ALTER TABLE endentities ADD CONSTRAINT endentities_unique_label UNIQUE (label);
GRANT SELECT, INSERT ON endentities TO myautographdbuser;
GRANT UPDATE (is_current) ON endentities TO myautographdbuser;
GRANT USAGE ON endentities_id_seq TO myautographdbuser;

CREATE TABLE endentities_lock(
      id          SERIAL PRIMARY KEY,
      is_locked   BOOLEAN NOT NULL,
      created_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
      freed_at    TIMESTAMP WITH TIME ZONE
);
GRANT SELECT, INSERT, UPDATE ON endentities_lock TO myautographdbuser;
GRANT USAGE ON endentities_lock_id_seq TO myautographdbuser;
-- 1573238043_create_signers.up.sql

-- stores IDs until we can move additional signer config to the DB
CREATE TABLE signers(
      id VARCHAR PRIMARY KEY UNIQUE NOT NULL
);
-- 1573238052_create_hawk_credentials.up.sql
CREATE TABLE hawk_credentials(
      id VARCHAR PRIMARY KEY UNIQUE,
      secret bytea NOT NULL,
      validity INTERVAL SECOND(0) DEFAULT INTERVAL '1 minute'
);
-- 1573238059_create_authorizations.up.sql
CREATE TABLE authorizations(
      id SERIAL PRIMARY KEY,
      credential_id VARCHAR references hawk_credentials(id),
      signer_id VARCHAR references signers(id),
      created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
-- 1573238336_grant_authgraphdbuser_select_on_signers_hawk_credentials_and_authorizations.up.sql
GRANT SELECT ON signers, hawk_credentials, authorizations TO myautographdbuser;
-- 1573486912_create_auth_admin_role.up.sql
CREATE ROLE myautographdbauthadmin;
ALTER ROLE myautographdbauthadmin WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB LOGIN PASSWORD 'myautographdbauthadminpassword';
-- 1573488968_grant_authgraphdbauthadmin_select_insert_update_delete_on_signers_hawk_credentials_and_authorizations.up.sql
GRANT SELECT, INSERT, UPDATE, DELETE ON signers, hawk_credentials, authorizations TO myautographdbauthadmin;
GRANT USAGE ON authorizations_id_seq TO myautographdbauthadmin;
