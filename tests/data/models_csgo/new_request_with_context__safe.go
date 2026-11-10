// expect-none: DF010
package main

import (
	"context"
	"net/http"
)

// The context is the first argument; the URL is constant.
func healthcheck(ctx context.Context) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://status.example.com/health", nil)
	http.DefaultClient.Do(req)
}
