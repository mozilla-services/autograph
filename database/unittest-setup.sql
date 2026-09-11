-- Grants additional permissions to the autograph user account for unit tests.
-- NOT FOR STAGING/PRODUCTION RELEASES

GRANT TRUNCATE ON endentities TO myautographdbuser;
GRANT TRUNCATE ON endentities_lock TO myautographdbuser;
GRANT INSERT, DELETE ON auth_signers TO myautographdbuser;
GRANT INSERT, DELETE ON auth TO myautographdbuser;
GRANT INSERT, DELETE ON signer TO myautographdbuser;
