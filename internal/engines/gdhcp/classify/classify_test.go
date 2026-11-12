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

package classify

import (
	"github.com/rkislov/gfw/internal/engines/gdhcp/config"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestClassificationSpecificityAndPredicates(t *testing.T) {
	v := 20
	wrong := 30
	classes := []config.Class{{Subnet: ""}, {Subnet: "empty"}, {Subnet: "general", VendorClass: "phone"}, {Subnet: "specific", VendorClass: "phone", OUI: "AA:BB:CC", VLAN: &v}, {Subnet: "tie", VendorClass: "phone", OUI: "AA:BB:CC", VLAN: &v}}
	got, ok := Match(classes, "aa:bb:cc:00:01:02", "Yealink PHONE", &v)
	require.True(t, ok)
	require.Equal(t, "specific", got.Subnet)
	for _, vlan := range []*int{nil, &wrong} {
		got, ok = Match(classes, "aa:bb:cc:00:01:02", "phone", vlan)
		require.True(t, ok)
		require.Equal(t, "general", got.Subnet)
	}
	got, ok = Match(classes, "00:00:00:00:01:02", "phone", &v)
	require.True(t, ok)
	require.Equal(t, "general", got.Subnet)
	_, ok = Match(classes, "aa:bb:cc:00:01:02", "printer", &v)
	require.False(t, ok)
}
