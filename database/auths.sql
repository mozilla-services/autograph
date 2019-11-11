
BEGIN;


INSERT INTO hawk_credentials(id, secret, validity) VALUES ('alice', 'fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu', interval '60 seconds');
INSERT INTO signers(id) VALUES ('testmar');
INSERT INTO authorizations(credential_id, signer_id) VALUES ('alice', 'testmar');
INSERT INTO signers(id) VALUES ('testmar2');
INSERT INTO authorizations(credential_id, signer_id) VALUES ('alice', 'testmar2');
INSERT INTO signers(id) VALUES ('testmarecdsa');
INSERT INTO authorizations(credential_id, signer_id) VALUES ('alice', 'testmarecdsa');
INSERT INTO signers(id) VALUES ('testcsp384');
INSERT INTO authorizations(credential_id, signer_id) VALUES ('alice', 'testcsp384');
INSERT INTO signers(id) VALUES ('hsm-webextensions-rsa');
INSERT INTO authorizations(credential_id, signer_id) VALUES ('alice', 'hsm-webextensions-rsa');
INSERT INTO signers(id) VALUES ('hsm-extensions-ecdsa');
INSERT INTO authorizations(credential_id, signer_id) VALUES ('alice', 'hsm-extensions-ecdsa');
INSERT INTO signers(id) VALUES ('normandy');
INSERT INTO authorizations(credential_id, signer_id) VALUES ('alice', 'normandy');
COMMIT;
