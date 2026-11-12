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

package metrics

import (
	"net/http"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// PoolStat is one subnet utilization sample.
type PoolStat struct {
	Subnet string
	VLAN   string
	Active int
	Total  int
}

// Source supplies gauge values at scrape time.
type Source interface {
	PoolStats() []PoolStat
}

// Metrics is the Prometheus instrumentation for the DHCP server.
type Metrics struct {
	Registry  *prometheus.Registry
	Requests  *prometheus.CounterVec
	Duration  prometheus.Histogram
	Relay     *prometheus.CounterVec
	Unknown   *prometheus.CounterVec
	Parser    *prometheus.CounterVec
	Hops      prometheus.Counter
	Untrusted prometheus.Counter
	src       atomic.Value
}

// New registers collectors on a private registry.
func New() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		Registry: reg,
		Requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "dhcp_requests_total",
			Help: "DHCP messages processed, labeled by type, subnet and VLAN.",
		}, []string{"type", "subnet", "vlan"}),
		Duration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "dhcp_request_duration_seconds",
			Help:    "Time spent handling one DHCP message.",
			Buckets: []float64{.0005, .001, .0025, .005, .01, .025, .05, .1, .25},
		}),
		Relay: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "dhcp_relay_requests_total",
			Help: "Relayed DHCP requests.",
		}, []string{"giaddr", "remote_id", "vlan"}),
		Unknown: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "dhcp_relay_unknown_vlan_total",
			Help: "Relayed requests whose VLAN could not be mapped.",
		}, []string{"giaddr"}),
		Parser: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "dhcp_relay_parser_errors_total",
			Help: "Circuit-id or option 82 parse failures.",
		}, []string{"parser"}),
		Hops: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "dhcp_relay_hops_exceeded_total",
			Help: "Packets dropped because hops exceeded max_relay_hops.",
		}),
		Untrusted: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "dhcp_relay_untrusted_total",
			Help: "Packets dropped because giaddr or remote-id is not trusted.",
		}),
	}
	reg.MustRegister(m.Requests, m.Duration, m.Relay, m.Unknown, m.Parser, m.Hops, m.Untrusted)
	reg.MustRegister(&poolCollector{m: m})
	return m
}

// Handler serves this registry in Prometheus text format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})
}

// SetSource attaches the live pool stats provider.
func (m *Metrics) SetSource(src Source) {
	if m == nil {
		return
	}
	m.src.Store(src)
}

type poolCollector struct {
	m *Metrics
}

func (c *poolCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- prometheus.NewDesc("dhcp_leases_active", "Active leases.", []string{"subnet", "vlan"}, nil)
	ch <- prometheus.NewDesc("dhcp_pool_utilization", "Share of the dynamic pool in use.", []string{"subnet"}, nil)
}

func (c *poolCollector) Collect(ch chan<- prometheus.Metric) {
	activeDesc := prometheus.NewDesc("dhcp_leases_active", "Active leases.", []string{"subnet", "vlan"}, nil)
	utilDesc := prometheus.NewDesc("dhcp_pool_utilization", "Share of the dynamic pool in use.", []string{"subnet"}, nil)
	src, _ := c.m.src.Load().(Source)
	if src == nil {
		return
	}
	for _, st := range src.PoolStats() {
		ch <- prometheus.MustNewConstMetric(activeDesc, prometheus.GaugeValue, float64(st.Active), st.Subnet, st.VLAN)
		util := 0.0
		if st.Total > 0 {
			util = float64(st.Active) / float64(st.Total)
		}
		ch <- prometheus.MustNewConstMetric(utilDesc, prometheus.GaugeValue, util, st.Subnet)
	}
}
