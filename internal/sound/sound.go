package sound

import (
	"crypto/sha1" // #nosec G505 - hashing for cache-busting only
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type Manager struct {
	path      string
	url       string
	available bool
	hash      string
}

func NewManager(path string) (*Manager, error) {
	m := &Manager{path: path}
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		// Not available; fallback will be used in the browser
		return m, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return m, err
	}
	defer f.Close()
	h := sha1.New()
	if _, err := io.Copy(h, f); err != nil {
		return m, err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	m.hash = sum
	m.available = true
	// e.g., /sounds/hey.mp3?v=<sha1>
	_, name := filepath.Split(path)
	m.url = fmt.Sprintf("/sounds/%s?v=%s", name, sum)
	return m, nil
}

func (m *Manager) Available() bool { return m.available }
func (m *Manager) URL() string     { return m.url }
func (m *Manager) Path() string    { return m.path }
func (m *Manager) Hash() string    { return m.hash }


