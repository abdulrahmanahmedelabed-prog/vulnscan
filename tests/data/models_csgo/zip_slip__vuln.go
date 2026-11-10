// expect: DF005
package main

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
)

func unzip(src, dest string) error {
	r, _ := zip.OpenReader(src)
	defer r.Close()
	for _, f := range r.File {
		target := filepath.Join(dest, f.Name)
		out, _ := os.Create(target)
		rc, _ := f.Open()
		io.Copy(out, rc)
	}
	return nil
}
