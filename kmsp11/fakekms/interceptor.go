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

package fakekms

import (
	"context"
	"strings"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

func newLockInterceptor(mux *sync.RWMutex) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		methodParts := strings.Split(info.FullMethod, "/")
		svc, method := methodParts[1], methodParts[2]

		switch svc {
		case "google.cloud.kms.v1.KeyManagementService":
			break
		case "fakekms.FaultService":
			return handler(ctx, req)
		default:
			return nil, errUnimplemented("unsupported service: %s", svc)
		}

		var locker sync.Locker
		switch method {
		case "AsymmetricDecrypt", "AsymmetricSign", "GenerateRandomBytes", "GetCryptoKey",
			"GetCryptoKeyVersion", "GetKeyRing", "GetPublicKey", "ListCryptoKeys",
			"ListCryptoKeyVersions", "ListKeyRings", "MacSign", "MacVerify", "RawDecrypt",
			"RawEncrypt":
			locker = mux.RLocker()
		case "CreateCryptoKey", "CreateCryptoKeyVersion", "CreateKeyRing", "DestroyCryptoKeyVersion",
			"UpdateCryptoKey", "UpdateCryptoKeyVersion":
			locker = mux
		default:
			return nil, errUnimplemented("unsupported method: %s", info.FullMethod)
		}

		locker.Lock()
		defer locker.Unlock()

		resp, err := handler(ctx, req)
		if err != nil {
			return nil, err
		}

		// The response message (or one of its nested messages) might be shared.
		// Guarantee thread safety by cloning the response while we hold the lock.
		respMsg, ok := resp.(proto.Message)
		if !ok {
			return nil, errInternal("resp.(type)=%T, want proto.Message", resp)
		}
		return proto.Clone(respMsg), nil
	}
}
