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

//go:build loadtest

package storage

import (
	"os"
	"runtime/trace"
	"sync/atomic"
	"time"
)

var flightStart = time.Now()
var flightTaken atomic.Bool
var flightPath = os.Getenv("GODHCP_FLIGHT_TRACE")
var flightRecorder = func() *trace.FlightRecorder {
	if flightPath == "" {
		return nil
	}
	f := trace.NewFlightRecorder(trace.FlightRecorderConfig{MinAge: 2 * time.Second, MaxBytes: 16 << 20})
	if err := f.Start(); err != nil {
		panic(err)
	}
	return f
}()

// Snapshot only the first long storage operation after startup. Export happens
// on a separate goroutine; neither snapshot I/O nor WriteTo blocks the writer.
func captureSlowStorage(elapsed time.Duration) {
	if flightRecorder == nil || elapsed < 20*time.Millisecond || time.Since(flightStart) < 5*time.Second || !flightTaken.CompareAndSwap(false, true) {
		return
	}
	go func() {
		f, err := os.Create(flightPath)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		if _, err = flightRecorder.WriteTo(f); err != nil {
			panic(err)
		}
		flightRecorder.Stop()
	}()
}
