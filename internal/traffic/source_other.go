//go:build !linux

package traffic

import "context"

func (c *Collector) startSources(_ context.Context) {}
