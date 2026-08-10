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
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type protoAllowlister map[string]struct{}

func allowlist(paths ...string) protoAllowlister {
	p := make(protoAllowlister)
	for _, path := range paths {
		p[path] = struct{}{}
	}
	return p
}

func (a protoAllowlister) check(msg proto.Message) error {
	return a.checkInternal("", msg.ProtoReflect())
}

func (a protoAllowlister) checkInternal(prefix string, msg protoreflect.Message) (err error) {
	if len(msg.GetUnknown()) > 0 {
		return errUnimplemented("message contains unknown fields")
	}

	if prefix != "" {
		prefix += "."
	}
	msg.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		path := prefix + string(fd.Name())

		if fd.Kind() == protoreflect.MessageKind { // if we have a nested message
			if _, ok := a[path]; ok {
				return true // the entire message is allowed; keep going
			}

			// otherwise check the nested message recursively
			err = a.checkInternal(path, v.Message())
			return err == nil // keep going if no error
		}

		// ensure the path is allowed
		_, ok := a[path]
		if !ok {
			err = errUnimplemented("field not supported: %s", path)
		}
		return ok // keep going if no error
	})
	return
}
