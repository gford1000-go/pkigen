package pkigen

import (
	cr "crypto/rand"
	mr "math/rand"

	"io"
	"sync"
)

type randomByteGenerator struct {
	r io.Reader
	l *sync.RWMutex
}

// reader used to generate random bytes
// On initialisation, reader is always set to the
// crypto/rand Reader, to ensure best possible
// random bytes.
// This should be the default behaviour for all production use
var reader = &randomByteGenerator{
	r: cr.Reader,
	l: &sync.RWMutex{},
}

// setTestReader should ONLY be used for testing, and
// replaces the existing reader with a pseudo random
// math/rand implementation, initialised with seed = 0
func (r *randomByteGenerator) setTestReader(seed int64) {
	r.l.Lock()
	defer r.l.Unlock()

	r.r = mr.New(mr.NewSource(seed))
}

// resetReader assigns the crypto/rand Reader, allowing
// tests to be run using the psuedo random generator
// to get consist test results, and then reset
func (r *randomByteGenerator) resetReader() {
	r.l.Lock()
	defer r.l.Unlock()

	r.r = cr.Reader
}

// Read attempts to fill the provided slice with random bytes
// and returns the number of bytes generated.
func (r *randomByteGenerator) Read(p []byte) (n int, err error) {
	r.l.RLock()
	defer r.l.RUnlock()

	return r.r.Read(p)
}
