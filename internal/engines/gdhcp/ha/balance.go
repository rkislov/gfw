// Copyright 2026 Кислов Роман Сергеевич
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ha

import "hash/fnv"

// Answers reports whether this server should respond to a new client.
// split is the primary's share of the 0..255 hash space (RFC 3074 style).
// Renewals of a lease this server already holds are not decided here.
func Answers(role string, split int, mac string) bool {
	if split < 0 {
		split = 0
	}
	if split > 256 {
		split = 256
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(mac))
	bucket := int(h.Sum32() % 256)
	if role == "secondary" {
		return bucket >= split
	}
	return bucket < split
}
