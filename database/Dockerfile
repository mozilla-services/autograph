FROM postgres:11

# CircleCI does not support mounting folders, so add files directly
# https://circleci.com/docs/2.0/building-docker-images/#mounting-folders
ADD schema.sql /docker-entrypoint-initdb.d/schema.sql

ADD server.key /opt/server.key
ADD server.crt /opt/server.crt

RUN chown -vR postgres /opt
RUN chmod -v 0600 /opt/server.key /opt/server.crt
