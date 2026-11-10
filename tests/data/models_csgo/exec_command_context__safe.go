// expect-none: DF003 DF003-ARG
package main

import (
	"context"
	"os/exec"
)

// The context is the first argument; the command line itself is constant.
func backup(ctx context.Context) error {
	return exec.CommandContext(ctx, "pg_dump", "--format=custom", "appdb").Run()
}
