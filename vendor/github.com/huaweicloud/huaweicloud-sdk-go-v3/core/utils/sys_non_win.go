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

//go:build !windows
// +build !windows

package utils

import (
	"errors"
	"gopkg.in/ini.v1"
	"os"
	"runtime"
	"strings"
)

const (
	osReleaseFilePath = "/etc/os-release"
	unknownVersion    = "unknown_version"
)

var langEnvKeys = []string{"LANG", "LC_ALL", "LC_MESSAGES", "LANGUAGE"}

type osRelease struct {
	Name      string
	Id        string
	Version   string
	VersionId string
	BuildId   string
}

func getOsRelease() (*osRelease, error) {
	file, err := ini.Load(osReleaseFilePath)
	if err != nil {
		return nil, err
	}

	section, err := file.GetSection("")
	if err != nil {
		return nil, err
	}

	return &osRelease{
		Name:      section.Key("NAME").String(),
		Version:   section.Key("VERSION").String(),
		VersionId: section.Key("VERSION_ID").String(),
	}, nil
}

func showOsInfo() OsInfo {
	osInfo := OsInfo{Platform: runtime.GOOS, Version: unknownVersion, Architecture: runtime.GOARCH}

	release, err := getOsRelease()
	if err != nil {
		return osInfo
	}

	if release.Name != "" {
		osInfo.Platform = release.Name
	}

	if release.Version != "" {
		osInfo.Version = release.Version
	} else if release.VersionId != "" {
		osInfo.Version = release.VersionId
	}

	return osInfo
}

func localeString() (string, error) {
	var lang string
	for _, key := range langEnvKeys {
		lang = os.Getenv(key)
		if lang != "" {
			break
		}
	}

	if lang == "" {
		return "", errors.New("failed to get locale string")
	}

	if strings.Contains(lang, ".") {
		return strings.Split(lang, ".")[0], nil
	}
	return lang, nil
}
