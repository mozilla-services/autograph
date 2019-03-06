FROM postgres:11

# CircleCI does not support mounting folders, so add it directly
# https://circleci.com/docs/2.0/building-docker-images/#mounting-folders
ADD schema.sql /docker-entrypoint-initdb.d/schema.sql