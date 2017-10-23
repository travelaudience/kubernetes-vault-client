package fs

import (
	"io/ioutil"
	"os"
	"path/filepath"
)

const (
	dPerms = 0700 // rwx------
	fPerms = 0600 // rw-------
)

// Write dumps the specified value to the file at path. Any missing intermediate
// directories will be created with dPerms permissions. The file itself is
// created with fPerms permissions.
func Write(path, val string) error {
	// Attempt to create the parent directory with dPerms permissions.
	if err := os.MkdirAll(filepath.Dir(path), dPerms); err != nil {
		return err
	}
	// Attempt to create a file at the specified path with fPerms permissions.
	return ioutil.WriteFile(path, []byte(val), fPerms)
}
