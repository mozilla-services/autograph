:: Copyright 2021 Google LLC
::
:: Licensed under the Apache License, Version 2.0 (the "License");
:: you may not use this file except in compliance with the License.
:: You may obtain a copy of the License at
::
::      http://www.apache.org/licenses/LICENSE-2.0
::
:: Unless required by applicable law or agreed to in writing, software
:: distributed under the License is distributed on an "AS IS" BASIS,
:: WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
:: See the License for the specific language governing permissions and
:: limitations under the License.

@echo on

:: Code under repo is checked out to %KOKORO_ARTIFACTS_DIR%\git.
:: The final directory name in this path is determined by the scm name specified
:: in the job configuration.
set PROJECT_ROOT=%KOKORO_ARTIFACTS_DIR%\git\oss-tools
cd "%PROJECT_ROOT%"

set RESULTS_DIR=%KOKORO_ARTIFACTS_DIR%\results
mkdir "%RESULTS_DIR%"

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

:: Install Microsoft's CNG SDK, stored in GCS for convenience.
:: Install all features, without displaying the GUI.
%KOKORO_GFILE_DIR%\cpdksetup.exe /features + /quiet

:: Configure user.bazelrc with remote build caching options and Google creds
copy .kokoro\remote_cache.bazelrc user.bazelrc
echo build --remote_default_exec_properties=cache-silo-key=%KOKORO_JOB_NAME% ^
  >> user.bazelrc
echo test --test_env=GOOGLE_APPLICATION_CREDENTIALS >> user.bazelrc

:: https://docs.bazel.build/versions/master/windows.html#build-c-with-msvc
set BAZEL_VC=C:\VS\VC\

:: Force msys2 environment instead of Cygwin
set PATH=C:\msys64\usr\bin;%PATH%
set BAZEL_SH=C:\msys64\usr\bin\bash.exe
set BAZEL_ARGS=-c opt --keep_going --enable_runfiles %BAZEL_EXTRA_ARGS%
:: https://bazel.build/configure/windows#long-path-issues
set BAZEL_STARTUP_ARGS=--output_user_root c:\bzltmp

:: Ensure Bazel version information is included in the build log
bazelisk %BAZEL_STARTUP_ARGS% version

bazelisk %BAZEL_STARTUP_ARGS% test %BAZEL_ARGS% ^
    ... :ci_only_tests :windows_ci_only_tests
set RV=%ERRORLEVEL%

:: Upload test logs for debugging and MOSS compliance.
python "%PROJECT_ROOT%\.kokoro\copy_test_outputs.py" ^
    "%PROJECT_ROOT%\bazel-testlogs" "%RESULTS_DIR%\testlogs"

:: Early exit if build/test failed.
if %RV% NEQ 0 exit %RV%

:: Run e2e test last and make sure the DLL is in system32.
if exist "%PROJECT_ROOT%\bazel-bin\kmscng\main\kmscng.dll" copy ^
    "%PROJECT_ROOT%\bazel-bin\kmscng\main\kmscng.dll" ^
    "C:\Windows\system32\kmscng.dll"
bazelisk %BAZEL_STARTUP_ARGS% test %BAZEL_ARGS% //kmscng/test/e2e:e2e_test

:: Re-upload test logs after e2e_test is complete.
python "%PROJECT_ROOT%\.kokoro\copy_test_outputs.py" ^
    "%PROJECT_ROOT%\bazel-testlogs" "%RESULTS_DIR%\testlogs"

:: Early exit if e2e_test failed.
if %ERRORLEVEL% NEQ 0 exit %ERRORLEVEL%

if exist "%PROJECT_ROOT%\bazel-bin\kmsp11\main\libkmsp11.so" copy ^
    "%PROJECT_ROOT%\bazel-bin\kmsp11\main\libkmsp11.so" ^
    "%RESULTS_DIR%\kmsp11_unsigned.dll"
if exist "%PROJECT_ROOT%\bazel-bin\kmsp11\test\e2e\e2e_test.exe" copy ^
    "%PROJECT_ROOT%\bazel-bin\kmsp11\test\e2e\e2e_test.exe" ^
    "%RESULTS_DIR%\kmsp11_e2e_test.exe"

if exist "%PROJECT_ROOT%\bazel-bin\kmscng\main\kmscng.dll" copy ^
    "%PROJECT_ROOT%\bazel-bin\kmscng\main\kmscng.dll" ^
    "%RESULTS_DIR%\kmscng.dll"
if exist "%PROJECT_ROOT%\bazel-bin\kmscng\main\kmscng.msi" copy ^
    "%PROJECT_ROOT%\bazel-bin\kmscng\main\kmscng.msi" ^
    "%RESULTS_DIR%\kmscng_unsigned.msi"
if exist "%PROJECT_ROOT%\bazel-bin\kmscng\test\e2e\e2e_test.exe" copy ^
    "%PROJECT_ROOT%\bazel-bin\kmscng\test\e2e\e2e_test.exe" ^
    "%RESULTS_DIR%\kmscng_e2e_test.exe"

copy "%PROJECT_ROOT%\LICENSE" "%RESULTS_DIR%\LICENSE"
