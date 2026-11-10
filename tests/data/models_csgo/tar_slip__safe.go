// expect-none: DF005
package main

import (
	"archive/tar"
	"io"
	"os"
	"path/filepath"
)

func untar(src io.Reader, dest string) error {
	tr := tar.NewReader(src)
	for {
		hdr, err := tr.Next()
		if err != nil {
			return err
		}
		if !filepath.IsLocal(hdr.Name) {
			continue
		}
		out, _ := os.OpenFile(filepath.Join(dest, hdr.Name), os.O_CREATE|os.O_WRONLY, 0644)
		io.Copy(out, tr)
	}
}
