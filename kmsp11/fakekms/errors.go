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
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func errAlreadyExists(name fmt.Stringer) error {
	return status.Errorf(codes.AlreadyExists, "already exists: %s", name)
}

func errFailedPrecondition(format string, a ...interface{}) error {
	return status.Errorf(codes.FailedPrecondition, format, a...)
}

func errInternal(format string, a ...interface{}) error {
	return status.Errorf(codes.Internal, format, a...)
}

func errInvalidArgument(format string, a ...interface{}) error {
	return status.Errorf(codes.InvalidArgument, format, a...)
}

func errMalformedName(resourceType, invalidName string) error {
	return status.Errorf(codes.InvalidArgument, "invalid %s name: %s", resourceType, invalidName)
}

func errMaxPageSize(resultCount int) error {
	return errUnimplemented("no pagination in fakekms: result count %d exceeds max page size (%d)",
		resultCount, maxPageSize)
}

func errNotFound(name fmt.Stringer) error {
	return status.Errorf(codes.NotFound, "not found: %s", name)
}

func errRequiredField(fieldName string) error {
	return status.Errorf(codes.InvalidArgument, "field %q is required", fieldName)
}

func errUnimplemented(format string, a ...interface{}) error {
	return status.Errorf(codes.Unimplemented, format, a...)
}
