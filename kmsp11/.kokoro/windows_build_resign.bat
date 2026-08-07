:: Re-sign Windows artifacts with our KMS-stored OSS key.

echo "Starting build re-signing job:"

:: The parent job's output artifacts get copied to KOKORO_GFILE_DIR.
:: go/kokoro-grouping#artifacts-transfer
cd "%KOKORO_GFILE_DIR%"

:: Display dir contents for logging.
dir /s

:: Create the standard output results directory.
:: Copy PKCS#11 and CNG artifacts to the output dir to sign them in place.
set RESULTS_DIR=%KOKORO_ARTIFACTS_DIR%\results
mkdir "%RESULTS_DIR%"
copy kmsp11_google_signed.dll "%RESULTS_DIR%\kmsp11.dll"
copy kmscng_google_signed.msi "%RESULTS_DIR%\kmscng.msi"
cd "%RESULTS_DIR%"

echo "Now re-sign both artifacts using our buildsigner tool:"

:: Code under repo is checked out to %KOKORO_ARTIFACTS_DIR%\git.
:: The final directory name in this path is determined by the scm name specified
:: in the job configuration.
set PROJECT_ROOT=%KOKORO_ARTIFACTS_DIR%\git\oss-tools
cd "%PROJECT_ROOT%"

:: Get Bazelisk
msiexec /i %KOKORO_GFILE_DIR%\go1.22.0.windows-amd64.msi /qn
set GOROOT=C:\Program Files\go
set GOPATH=%KOKORO_ARTIFACTS_DIR%\gopath
go install github.com/bazelbuild/bazelisk@v1.25.0
set PATH=%GOPATH%\bin;%PATH%

:: Unwrap our wrapped service account key
set GOOGLE_APPLICATION_CREDENTIALS=%KOKORO_ARTIFACTS_DIR%/oss-tools-ci-key.json
go run ./.kokoro/unwrap_key.go ^
  -wrapping_key_file=%KOKORO_KEYSTORE_DIR%/75220_token-wrapping-key ^
  -wrapped_key_file=%KOKORO_GFILE_DIR%/oss-tools-ci-key.json.enc ^
  > %GOOGLE_APPLICATION_CREDENTIALS%

:: Create and configure user.bazelrc with Google creds
echo build --google_default_credentials=true > user.bazelrc
echo test --test_env=GOOGLE_APPLICATION_CREDENTIALS >> user.bazelrc

:: Force msys2 environment instead of Cygwin
set PATH=C:\msys64\usr\bin;%PATH%
set BAZEL_SH=C:\msys64\usr\bin\bash.exe
set BAZEL_ARGS=-c opt --keep_going --enable_runfiles %BAZEL_EXTRA_ARGS%
:: https://bazel.build/configure/windows#long-path-issues
set BAZEL_STARTUP_ARGS=--output_user_root c:\bzltmp

:: Sign PKCS#11 DLL
bazelisk %BAZEL_STARTUP_ARGS% run %BAZEL_ARGS% //kmsp11/tools/buildsigner -- ^
  -signing_key=%BUILD_SIGNING_KEY% ^
  < "%RESULTS_DIR%\kmsp11.dll" ^
  > "%RESULTS_DIR%\kmsp11.dll.sig"

:: Sign CNG MSI
bazelisk %BAZEL_STARTUP_ARGS% run %BAZEL_ARGS% //kmsp11/tools/buildsigner -- ^
  -signing_key=%BUILD_SIGNING_KEY% ^
  < "%RESULTS_DIR%\kmscng.msi" ^
  > "%RESULTS_DIR%\kmscng.msi.sig"
