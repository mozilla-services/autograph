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
func getSecretMap(client *secretmanager.Client, ctx context.Context, projectId string, secretName string) (secret map[string]string, err error) {
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s/versions/latest", projectId, secretName),
	}
	resp, err := client.AccessSecretVersion(ctx, req)
	if err != nil {
		return
	}

	err = yaml.Unmarshal(resp.Payload.Data, &secret)
	return
}
