CREATE ROLE myautographdbuser;
ALTER ROLE myautographdbuser WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB LOGIN PASSWORD 'myautographdbpassword';

CREATE TABLE IF NOT EXISTS endentities(
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

CREATE TABLE IF NOT EXISTS endentities_lock(
      id          SERIAL PRIMARY KEY,
      is_locked   BOOLEAN NOT NULL,
      created_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
      freed_at    TIMESTAMP WITH TIME ZONE

);
GRANT SELECT, INSERT, UPDATE ON endentities_lock TO myautographdbuser;
GRANT USAGE ON endentities_lock_id_seq TO myautographdbuser;

CREATE TABLE IF NOT EXISTS auth(
      id          VARCHAR(128) PRIMARY KEY,
      key         VARCHAR(64) NOT NULL,
	  comments    varchar,
      created     TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
      updated     TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
GRANT SELECT ON auth TO myautographdbuser;

CREATE TABLE IF NOT EXISTS signer (
      id          VARCHAR(128) PRIMARY KEY,
      type        VARCHAR(64) NOT NULL,
      mode        VARCHAR(64) NOT NULL,
      comments    VARCHAR,
      created     TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
      updated     TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
      secret      VARCHAR(256), -- points to a secret that can be read by application
      public      JSONB
);
GRANT SELECT ON signer TO myautographdbuser;

CREATE TABLE IF NOT EXISTS auth_signers(
      auth    varchar(128),
      signer  varchar(128),
      created TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
      CONSTRAINT auth_signers_pk PRIMARY KEY(auth, signer),
      CONSTRAINT auth_signers_fk_auth FOREIGN KEY(auth) REFERENCES auth(id),
      CONSTRAINT auth_signers_fk_signer FOREIGN KEY(signer) REFERENCES signer(id)
);
GRANT SELECT ON auth_signers TO myautographdbuser;
