-- 1573486912_create_auth_admin_role.up.sql
CREATE ROLE myautographdbauthadmin;
ALTER ROLE myautographdbauthadmin WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB LOGIN PASSWORD 'myautographdbauthadminpassword';
