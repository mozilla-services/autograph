# TROUBLESHOOTING

## Logging

To aid troubleshooting, users can specify a custom log directory where
application logs should be written. This done by setting the `log_directory`
field in the YAML configuration used by the library, eg:
```
log_directory: "/var/log/kmsp11"
```
See the
[configuration section](kmsp11/docs/user_guide.md#global-configuration) of the
user guide for more info.

## Underlying gRPC Issues

As an additional debugging step, gRPC (used by the library) also allows users to
enable additional levels of logging through a range of environment variables.
See the
[gRPC troubleshooting guide](https://github.com/grpc/grpc/blob/master/TROUBLESHOOTING.md)
for more info.
