package web

import "testing"

func benchAll(b *testing.B, fns []func(b *testing.B)) {
	for _, f := range fns {
		b.Run("x", func(b *testing.B) { f(b) })
	}
}

func helper() string { return "constant" }
