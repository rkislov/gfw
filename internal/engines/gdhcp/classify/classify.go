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
	"strings"

	"github.com/rkislov/gfw/internal/engines/gdhcp/config"
)

// Match selects a subnet from client-classification rules.
// Every predicate that is set on a class must match. The class with the most
// predicates wins.
func Match(classes []config.Class, mac, vendorClass string, vlan *int) (config.Class, bool) {
	mac = strings.ToLower(mac)
	vendorClass = strings.ToLower(vendorClass)
	bestScore := 0
	var best config.Class
	for _, c := range classes {
		if c.Subnet == "" {
			continue
		}
		score := 0
		if c.VendorClass != "" {
			if !strings.Contains(vendorClass, strings.ToLower(c.VendorClass)) {
				continue
			}
			score++
		}
		if c.OUI != "" {
			oui := strings.ToLower(c.OUI)
			if !strings.HasPrefix(mac, oui) {
				continue
			}
			score++
		}
		if c.VLAN != nil {
			if vlan == nil || *vlan != *c.VLAN {
				continue
			}
			score++
		}
		if score == 0 {
			continue
		}
		if score > bestScore {
			bestScore = score
			best = c
		}
	}
	return best, best.Subnet != ""
}
