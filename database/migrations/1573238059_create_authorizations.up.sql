-- 1573238059_create_authorizations.up.sql
CREATE TABLE authorizations(
      id SERIAL PRIMARY KEY,
      credential_id VARCHAR references hawk_credentials(id),
      signer_id VARCHAR references signers(id),
      created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
