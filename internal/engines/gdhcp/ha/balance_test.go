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

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestComplementaryAssignmentsAndBounds(t *testing.T) {
	count := 0
	for i := 0; i < 1000; i++ {
		mac := fmt.Sprintf("02:00:00:00:%02x:%02x", i/256, i%256)
		primary := Answers("primary", 128, mac)
		require.NotEqual(t, primary, Answers("secondary", 128, mac))
		if primary {
			count++
		}
		require.Equal(t, primary, Answers("primary", 128, mac))
	}
	require.InDelta(t, 500, count, 150)
	for _, split := range []int{-1, 0} {
		require.False(t, Answers("primary", split, "client"))
		require.True(t, Answers("secondary", split, "client"))
	}
	for _, split := range []int{256, 300} {
		require.True(t, Answers("primary", split, "client"))
		require.False(t, Answers("secondary", split, "client"))
	}
}
