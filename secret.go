// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"fmt"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/mozilla-services/yaml"
)

// Queries GCP secret manager and returns a map of the expected secret's string key/value pairs
func getSecretMap(projectId string, secretName string) (secret map[string]string, err error) {
	ctx := context.Background()
	c, err := secretmanager.NewClient(ctx)
	if err != nil {
		return
	}
	defer c.Close()

	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s/versions/latest", projectId, secretName),
	}
	resp, err := c.AccessSecretVersion(ctx, req)
	if err != nil {
		return
	}

	err = yaml.Unmarshal(resp.Payload.Data, &secret)
	return
}
