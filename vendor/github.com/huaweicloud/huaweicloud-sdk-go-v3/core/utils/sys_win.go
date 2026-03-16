// Copyright 2025 Huawei Technologies Co.,Ltd.
//
// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//go:build windows
// +build windows

package utils

import (
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

const (
	ntdll                    = "ntdll.dll"
	kernel32                 = "kernel32.dll"
	rtlGetVersion            = "RtlGetVersion"
	getUserDefaultLocaleName = "GetUserDefaultLocaleName"
	unknownVersion           = "unknown_version"
	successInfo              = "The operation completed successfully."
)

func osVersion() string {
	type OSVERSIONINFOEX struct {
		dwOSVersionInfoSize uint32
		dwMajorVersion      uint32
		dwMinorVersion      uint32
		dwBuildNumber       uint32
	}

	dll := syscall.NewLazyDLL(ntdll)
	if proc := dll.NewProc(rtlGetVersion); proc != nil {
		info := OSVERSIONINFOEX{dwOSVersionInfoSize: uint32(unsafe.Sizeof(OSVERSIONINFOEX{}))}
		ret, _, _ := proc.Call(uintptr(unsafe.Pointer(&info)))
		if ret == 0 {
			return fmt.Sprintf("%d.%d.%d", info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber)
		}
	}

	return unknownVersion
}

func localeString() (string, error) {
	dll := syscall.NewLazyDLL(kernel32)
	proc := dll.NewProc(getUserDefaultLocaleName)

	buffer := make([]uint16, 128)
	_, _, err := proc.Call(
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
	)
	if err == nil || strings.Contains(err.Error(), successInfo) {
		return syscall.UTF16ToString(buffer), nil
	}

	return "", err
}

func showOsInfo() OsInfo {
	return OsInfo{Platform: runtime.GOOS, Version: osVersion(), Architecture: runtime.GOARCH}
}
