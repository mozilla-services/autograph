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

package contract

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// ProtoDiffOpts returns cmp.Options suitable for diffing KMS proto messages.
func ProtoDiffOpts() []cmp.Option {
	return []cmp.Option{protocmp.Transform(), EquateApproxTimestamp(time.Minute)}
}

// RandomID returns a string suitable for use as a KMS resource identifier.
func RandomID(t *testing.T) string {
	t.Helper()
	id, err := uuid.NewRandom()
	if err != nil {
		t.Fatal(err)
	}
	return id.String()
}

// EquateApproxTimestamp returns a Comparer option that determines two non-zero
// proto timestamp values to be equal if they are within some margin of one
// another.
//
// See also cmpopts.EquateApproxTime:
// https://pkg.go.dev/github.com/google/go-cmp/cmp/cmpopts?tab=doc#EquateApproxTime
func EquateApproxTimestamp(margin time.Duration) cmp.Option {
	if margin < 0 {
		panic("margin must be a non-negative number")
	}
	return protocmp.FilterMessage(&timestamppb.Timestamp{}, cmp.Comparer(func(x, y protocmp.Message) bool {
		diff, ok := timestampDiff(x, y)
		if !ok {
			// fall back to cmp.Equal if one of the messages is invalid or zero
			return cmp.Equal(x, y)
		}
		return diff <= margin
	}))
}

func comparableTime(msg proto.Message) (time.Time, bool) {
	ts := new(timestamppb.Timestamp)
	proto.Merge(ts, msg)
	if err := ts.CheckValid(); err != nil {
		return time.Time{}, false
	}
	return ts.AsTime(), true
}

// Returns the difference in times between the two timestamp messages as
// a time.Duration, or not OK if one of the messages is invalid or zero.
func timestampDiff(mx, my proto.Message) (diff time.Duration, ok bool) {
	if x, ok := comparableTime(mx); ok {
		if y, ok := comparableTime(my); ok {
			if !(x.IsZero() || y.IsZero()) {
				// ensure x <= y
				if x.After(y) {
					x, y = y, x
				}
				return y.Sub(x), true
			}
		}
	}
	return 0, false
}
