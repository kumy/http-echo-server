package tlsmgr

import (
	"container/list"
	"crypto/tls"
	"crypto/x509"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// certCache is an LRU cache of leaf certificates keyed by SNI, with
// single-flight issuance (docs/specification.md §9.3/§9.4).
type certCache struct {
	mu       sync.Mutex
	capacity int
	entries  map[string]*list.Element
	order    *list.List // front = most recently used
	sf       singleflight.Group

	issue func(sni string) (*tls.Certificate, error)
	// needsRefresh decides when a cached certificate must be re-issued.
	needsRefresh func(leaf *x509.Certificate) bool
	// staleOK serves an expired-policy (but not yet expired) certificate
	// when re-issuance fails, reporting the error via onRefreshError.
	staleOK        bool
	onRefreshError func(sni string, err error)
}

type cacheEntry struct {
	key  string
	cert *tls.Certificate
	leaf *x509.Certificate
}

func newCertCache(capacity int, issue func(string) (*tls.Certificate, error)) *certCache {
	return &certCache{
		capacity: capacity,
		entries:  make(map[string]*list.Element),
		order:    list.New(),
		issue:    issue,
		needsRefresh: func(leaf *x509.Certificate) bool {
			return time.Until(leaf.NotAfter) < 5*time.Minute
		},
		onRefreshError: func(string, error) {},
	}
}

// Get returns the certificate for sni, issuing (single-flight) on miss or
// when the refresh policy demands it.
func (c *certCache) Get(sni string) (*tls.Certificate, error) {
	if cert := c.lookup(sni); cert != nil {
		return cert, nil
	}

	v, err, _ := c.sf.Do(sni, func() (any, error) {
		// A concurrent flight may have stored a fresh certificate already.
		if cert := c.lookup(sni); cert != nil {
			return cert, nil
		}
		cert, err := c.issue(sni)
		if err != nil {
			return nil, err
		}
		leaf := cert.Leaf
		if leaf == nil {
			leaf, err = x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				return nil, err
			}
		}
		c.store(sni, cert, leaf)
		return cert, nil
	})
	if err != nil {
		if c.staleOK {
			if stale := c.lookupStale(sni); stale != nil {
				c.onRefreshError(sni, err)
				return stale, nil
			}
		}
		return nil, err
	}
	return v.(*tls.Certificate), nil
}

// lookup returns a cached certificate that does not need a refresh.
func (c *certCache) lookup(sni string) *tls.Certificate {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[sni]
	if !ok {
		return nil
	}
	entry := el.Value.(*cacheEntry)
	if c.needsRefresh(entry.leaf) {
		return nil
	}
	c.order.MoveToFront(el)
	return entry.cert
}

// lookupStale returns a cached certificate that is still within its real
// validity window, regardless of the refresh policy.
func (c *certCache) lookupStale(sni string) *tls.Certificate {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[sni]
	if !ok {
		return nil
	}
	entry := el.Value.(*cacheEntry)
	if time.Now().After(entry.leaf.NotAfter) {
		return nil
	}
	return entry.cert
}

func (c *certCache) store(sni string, cert *tls.Certificate, leaf *x509.Certificate) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[sni]; ok {
		el.Value = &cacheEntry{key: sni, cert: cert, leaf: leaf}
		c.order.MoveToFront(el)
		return
	}
	c.entries[sni] = c.order.PushFront(&cacheEntry{key: sni, cert: cert, leaf: leaf})
	for len(c.entries) > c.capacity {
		oldest := c.order.Back()
		c.order.Remove(oldest)
		delete(c.entries, oldest.Value.(*cacheEntry).key)
	}
}

// len returns the number of cached certificates (for tests).
func (c *certCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
