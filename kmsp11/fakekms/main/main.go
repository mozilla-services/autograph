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

// Package main starts a new fakekms server that listens on an OS-supplied port.
//
// The program starts up and prints its listening address to standard output. It
// then runs until it receives SIGINT or SIGTERM.
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"cloud.google.com/kms/integrations/fakekms"
)

func main() {
	sigs := make(chan os.Signal)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	srv, err := fakekms.NewServer()
	if err != nil {
		log.Fatal(err)
	}
	defer srv.Close()
	fmt.Println(srv.Addr)
	fmt.Fprintln(os.Stderr, "ready to serve requests")

	sig := <-sigs
	fmt.Fprintln(os.Stderr, "shutting down on signal:", sig)
}
