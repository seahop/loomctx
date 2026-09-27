package main

// Hand-rolled Prometheus text exposition (D-015): a handful of atomic
// counters is not worth a client-library dependency in the hot path.

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

type gwMetrics struct {
	requests     atomic.Int64
	queued       atomic.Int64
	rejectedBad  atomic.Int64 // malformed / contract violations / oversize
	rejectedAuth atomic.Int64
	rejectedRate atomic.Int64
	upstreamErr  atomic.Int64
}

func (m *gwMetrics) handler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	for _, c := range []struct {
		name, help string
		val        int64
	}{
		{"loomctx_gateway_requests_total", "Ingest requests received", m.requests.Load()},
		{"loomctx_gateway_forwarded_total", "Envelopes forwarded/queued", m.queued.Load()},
		{"loomctx_gateway_rejected_invalid_total", "Rejected: malformed or contract violation", m.rejectedBad.Load()},
		{"loomctx_gateway_rejected_unauthorized_total", "Rejected: missing/wrong API key", m.rejectedAuth.Load()},
		{"loomctx_gateway_rejected_ratelimited_total", "Rejected: rate limit", m.rejectedRate.Load()},
		{"loomctx_gateway_upstream_errors_total", "Forwarding failures", m.upstreamErr.Load()},
	} {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n",
			c.name, c.help, c.name, c.name, c.val)
	}
}
