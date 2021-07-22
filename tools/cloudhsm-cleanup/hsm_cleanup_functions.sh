#!/usr/bin/env bash

# decrypt sops-encrypted autograph config at $1 and set env vars to
# access the autograph DB
function set_db_env_vars(){
    DB_HOST="$(sudo sops --extract '["database"]["host"]' -d "$1" | cut -d ':' -f 1)"
    DB_PORT="$(sudo sops --extract '["database"]["host"]' -d "$1" | cut -d ':' -f 2)"
    DB_NAME="$(sudo sops --extract '["database"]["name"]' -d "$1")"
    DB_USER="$(sudo sops --extract '["database"]["user"]' -d "$1")"
    PGPASSWORD="$(sudo sops --extract '["database"]["password"]' -d "$1")"

    export DB_HOST
    export DB_PORT
    export DB_NAME
    export DB_USER
    export PGPASSWORD
}

# decrypt sops-encrypted autograph config at $1 and set env vars to
# access CloudHSM
function set_cloudhsm_env_vars(){
    CLOUDHSM_USER="$(sudo sops --extract '["hsm"]["pin"]' -d "$1" | cut -d ':' -f 1)"
    CLOUDHSM_PASSWORD="$(sudo sops --extract '["hsm"]["pin"]' -d "$1" | cut -d ':' -f 2)"
    CLOUDHSM_LABEL="$(sudo sops --extract '["hsm"]["tokenlabel"]' -d "$1")"

    export CLOUDHSM_USER
    export CLOUDHSM_PASSWORD
    export CLOUDHSM_LABEL
}

# open a psql shell in the autograph DB using env vars from set_db_env_vars
function db_shell(){
    psql --host="$DB_HOST" \
         --port="$DB_PORT" \
         --username="$DB_USER" \
         --dbname="$DB_NAME"
}

# list inactive DB end entities rows created more than 90 days ago
# write them to stdout in CSV format row using env vars
# from set_db_env_vars
function list_inactive_ees_csv(){
    psql --host="$DB_HOST" \
         --port="$DB_PORT" \
         --username="$DB_USER" \
         --dbname="$DB_NAME" \
         --command="COPY (SELECT id, label, hsm_handle, created_at FROM endentities WHERE is_current=FALSE AND created_at < (NOW()::DATE - 90) ORDER BY signer_id, created_at ASC) TO STDOUT CSV"
}
