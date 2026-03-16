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

package utils

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
)

const (
	defaultCloudDirName = ".huaweicloud"
	defaultAppFileName  = "application_id"
)

var (
	infoOnce      sync.Once
	envInfo       string
	uuidPattern   = `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`
	localePattern = `^[a-z]{2,3}(?:[-_][A-Z]{2,3})?$`
	cloudDirName  = defaultCloudDirName
	appFileName   = defaultAppFileName
)

type OsInfo struct {
	Platform     string
	Version      string
	Architecture string
}

func GetEnvInfoString() string {
	infoOnce.Do(func() {
		envInfo = processEnvInfoString()
	})
	return envInfo
}

func getLocaleString() (string, error) {
	loc, err := localeString()
	if err != nil {
		return "", err
	}

	matched, err := regexp.MatchString(localePattern, loc)
	if err != nil {
		return "", err
	}
	if !matched {
		return "", fmt.Errorf("invalid locale: %s", loc)
	}
	return loc, nil
}

func processEnvInfoString() string {
	uas := []string{getOSInfo()}
	if appIdInfo, ok := getAppInfo(); ok {
		uas = append(uas, appIdInfo)
	}
	return ReplaceNonASCII(strings.Join(uas, "; "), '_')
}

func getOSInfo() string {
	info := showOsInfo()
	osVal := strings.ReplaceAll(
		fmt.Sprintf("%s#%s#%s", info.Platform, info.Version, info.Architecture), " ", "_")
	ret := fmt.Sprintf("os/%s go/%s", osVal, runtime.Version())
	if loc, err := getLocaleString(); err == nil {
		return fmt.Sprintf("%s meta/%s", ret, loc)
	}
	return ret
}

func getAppInfo() (string, bool) {
	if appId, ok := getAppId(); ok {
		return "app/" + appId, true
	}
	return "", false
}

func getAppId() (string, bool) {
	if appId, ok := readAppId(); ok {
		return appId, ok
	}

	return generateAndStoreAppId()
}

func readAppId() (string, bool) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", false
	}
	appIdFilepath := filepath.Join(homeDir, cloudDirName, appFileName)
	_, err = os.Stat(appIdFilepath)
	if os.IsNotExist(err) {
		return "", false
	}
	data, err := ioutil.ReadFile(appIdFilepath)
	if err != nil {
		return "", false
	}
	data = bytes.TrimSpace(data)
	if ok, err := regexp.Match(uuidPattern, data); ok && err == nil {
		return string(data), true
	}
	return "", false
}

func generateAndStoreAppId() (string, bool) {
	uuid, err := generateUUIDv4()
	if err != nil {
		return "", false
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", false
	}
	cloudDir := filepath.Join(homeDir, cloudDirName)
	_, err = os.Stat(cloudDir)
	if os.IsNotExist(err) {
		if err = os.MkdirAll(cloudDir, 0700); err != nil {
			return "", false
		}
	} else if err != nil {
		return "", false
	}

	appIdFilepath := filepath.Join(cloudDir, appFileName)
	if err = ioutil.WriteFile(appIdFilepath, []byte(uuid), 0600); err != nil {
		return "", false
	}
	return uuid, true
}
