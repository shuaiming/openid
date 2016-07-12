package openid

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"strings"
	"sync"
	"time"
)

const (
	hmacSHA1   = "HMAC-SHA1"
	hmacSHA256 = "HMAC-SHA256"
)

// Association represents an openid association.
type Association struct {
	// Endpoint is the OP Endpoint for which this association is valid.
	// It might be blank.
	Endpoint string
	// Handle is used to identify the association with the OP Endpoint.
	Handle string
	// Secret is the secret established with the OP Endpoint.
	Secret []byte
	// Type is the type of this association.
	Type string
	// Expires holds the expiration time of the association.
	Expires time.Time
}

func (a *Association) sign(
	params map[string]string, signed []string) (string, error) {

	var h hash.Hash

	switch a.Type {
	case hmacSHA1:
		h = hmac.New(sha1.New, a.Secret)
	case hmacSHA256:
		h = hmac.New(sha256.New, a.Secret)
	default:
		return "", fmt.Errorf("unsupported association type %q", a.Type)
	}

	for _, k := range signed {
		writeKeyValuePair(h, k, params[k])
	}

	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

// associations store association with key of OpenID endpoint
type associations struct {
	sync.RWMutex
	store map[string]Association
}

// get Association with key of endpoint
func (assocs *associations) get(endpoint string) (Association, bool) {
	ep := strings.TrimRight(endpoint, "/")
	assocs.RLock()
	assoc, ok := assocs.store[ep]
	assocs.RUnlock()

	// clear expired associate
	if assoc.Expires.Before(time.Now()) && ok {
		assoc = Association{}
		ok = false
		assocs.delete(ep)
	}

	return assoc, ok
}

// set Association with key of endpoint
func (assocs *associations) set(endpoint string, assoc Association) {
	assocs.Lock()
	defer assocs.Unlock()
	assocs.store[strings.TrimRight(endpoint, "/")] = assoc
}

// delete Association with key of endpoint
func (assocs *associations) delete(endpoint string) {
	assocs.Lock()
	defer assocs.Unlock()
	delete(assocs.store, strings.TrimRight(endpoint, "/"))
}
