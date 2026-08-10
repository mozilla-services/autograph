// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// A DLL custom action to register and unregister our provider.
// https://learn.microsoft.com/en-us/windows/win32/msi/dynamic-link-libraries

// clang-format off
#include <windows.h>
#include <msi.h>
#include <Msiquery.h>
#pragma comment(lib, "msi.lib")
// clang-format on

#include "absl/status/status.h"
#include "kmscng/util/registration.h"

extern "C" UINT __stdcall RegisterProvider(MSIHANDLE hInstall) {
  absl::Status result = cloud_kms::kmscng::RegisterProvider();
  if (result.ok()) {
    return S_OK;
  }
  PMSIHANDLE record_handle = MsiCreateRecord(0);
  MsiRecordSetString(record_handle, 0, result.ToString().c_str());
  MsiProcessMessage(hInstall, INSTALLMESSAGE_INFO, record_handle);
  return E_FAIL;
}

extern "C" UINT __stdcall UnregisterProvider(MSIHANDLE hInstall) {
  absl::Status result = cloud_kms::kmscng::UnregisterProvider();
  if (result.ok()) {
    return S_OK;
  }
  PMSIHANDLE record_handle = MsiCreateRecord(0);
  MsiRecordSetString(record_handle, 0, result.ToString().c_str());
  MsiProcessMessage(hInstall, INSTALLMESSAGE_INFO, record_handle);
  return E_FAIL;
}
