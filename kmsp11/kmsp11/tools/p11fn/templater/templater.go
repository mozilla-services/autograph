// Copyright 2021 Google LLC
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

// Package main reads the PKCS#11 function prototypes a CkFuncList textproto
// and adds them as context while executing the provided text template.
package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"
	"text/template"

	"google.golang.org/protobuf/encoding/prototext"

	"cloud.google.com/kms/integrations/kmsp11/tools/p11fn/p11fnpb"
)

var (
	funcListPath = flag.String("func_list_path", "", "path to function list proto")
	templatePath = flag.String("template_path", "", "path to template file")
)

func mustReadFile(filePath string) []byte {
	f, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Fatalf("error reading file at %s: %+v", filePath, err)
	}
	return f
}

func main() {
	flag.Parse()

	funcs := new(p11fnpb.CkFuncList)
	if err := prototext.Unmarshal(mustReadFile(*funcListPath), funcs); err != nil {
		log.Fatalf("error parsing function list textproto: %+v", err)
	}

	templateFile := mustReadFile(*templatePath)
	t, err := new(template.Template).Parse(string(templateFile))
	if err != nil {
		log.Fatalf("error parsing template: %+v", err)
	}

	if err := t.Execute(os.Stdout, funcs); err != nil {
		log.Fatalf("error executing template: %+v", err)
	}
}
