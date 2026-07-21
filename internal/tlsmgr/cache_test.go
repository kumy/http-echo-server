package tlsmgr

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fakeCert(notBefore, notAfter time.Time) *tls.Certificate {
	return &tls.Certificate{Leaf: &x509.Certificate{NotBefore: notBefore, NotAfter: notAfter}}
}

func freshCert() *tls.Certificate {
	return fakeCert(time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
}

func TestCacheHit(t *testing.T) {
	var calls atomic.Int32
	cache := newCertCache(4, func(string) (*tls.Certificate, error) {
		calls.Add(1)
		return freshCert(), nil
	})

	for i := 0; i < 3; i++ {
		if _, err := cache.Get("a.example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Errorf("issuer called %d times, want 1", calls.Load())
	}
}

func TestCacheLRUEviction(t *testing.T) {
	var calls atomic.Int32
	cache := newCertCache(2, func(string) (*tls.Certificate, error) {
		calls.Add(1)
		return freshCert(), nil
	})

	_, _ = cache.Get("a")
	_, _ = cache.Get("b")
	_, _ = cache.Get("a") // refresh recency: a is now MRU
	_, _ = cache.Get("c") // evicts b
	if cache.len() != 2 {
		t.Errorf("len = %d, want 2", cache.len())
	}

	calls.Store(0)
	_, _ = cache.Get("a")
	if calls.Load() != 0 {
		t.Error("a should still be cached")
	}
	_, _ = cache.Get("b")
	if calls.Load() != 1 {
		t.Error("b should have been evicted and re-issued")
	}
}

func TestCacheRefreshPolicy(t *testing.T) {
	var calls atomic.Int32
	cache := newCertCache(4, func(string) (*tls.Certificate, error) {
		calls.Add(1)
		// Expires within the default 5-minute refresh window.
		return fakeCert(time.Now().Add(-time.Hour), time.Now().Add(time.Minute)), nil
	})

	_, _ = cache.Get("x")
	_, _ = cache.Get("x")
	if calls.Load() != 2 {
		t.Errorf("near-expiry cert must be re-issued, calls = %d", calls.Load())
	}
}

func TestCacheStaleServing(t *testing.T) {
	var calls atomic.Int32
	var refreshErrs atomic.Int32
	cache := newCertCache(4, func(string) (*tls.Certificate, error) {
		if calls.Add(1) == 1 {
			// Still valid for an hour, but the policy below wants a refresh.
			return fakeCert(time.Now().Add(-2*time.Hour), time.Now().Add(time.Hour)), nil
		}
		return nil, errors.New("vault down")
	})
	cache.needsRefresh = func(*x509.Certificate) bool { return true }
	cache.staleOK = true
	cache.onRefreshError = func(string, error) { refreshErrs.Add(1) }

	first, err := cache.Get("x")
	if err != nil {
		t.Fatal(err)
	}
	second, err := cache.Get("x")
	if err != nil {
		t.Fatalf("stale cert should be served, got error: %v", err)
	}
	if first != second {
		t.Error("expected the cached (stale) certificate")
	}
	if refreshErrs.Load() == 0 {
		t.Error("onRefreshError not called")
	}
}

func TestCacheErrorWithoutStale(t *testing.T) {
	cache := newCertCache(4, func(string) (*tls.Certificate, error) {
		return nil, errors.New("mint failed")
	})
	if _, err := cache.Get("x"); err == nil {
		t.Fatal("expected issuance error")
	}
}

func TestCacheExpiredNotServedStale(t *testing.T) {
	var calls atomic.Int32
	cache := newCertCache(4, func(string) (*tls.Certificate, error) {
		if calls.Add(1) == 1 {
			return fakeCert(time.Now().Add(-2*time.Hour), time.Now().Add(-time.Minute)), nil
		}
		return nil, errors.New("vault down")
	})
	cache.needsRefresh = func(*x509.Certificate) bool { return true }
	cache.staleOK = true

	_, _ = cache.Get("x")
	if _, err := cache.Get("x"); err == nil {
		t.Fatal("a really expired cert must not be served stale")
	}
}

func TestCacheSingleFlight(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	cache := newCertCache(4, func(string) (*tls.Certificate, error) {
		calls.Add(1)
		<-release
		return freshCert(), nil
	})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = cache.Get("same.example.com")
		}()
	}
	time.Sleep(50 * time.Millisecond) // let the goroutines pile up on the flight
	close(release)
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Errorf("issuer called %d times under concurrency, want 1", got)
	}
}

func TestVaultRefreshPolicy(t *testing.T) {
	issued := time.Now()
	leaf := &x509.Certificate{NotBefore: issued, NotAfter: issued.Add(3 * time.Hour)}

	early := vaultRefreshPolicy(func() time.Time { return issued.Add(time.Hour) })
	if early(leaf) {
		t.Error("1h into a 3h cert must not refresh yet")
	}
	late := vaultRefreshPolicy(func() time.Time { return issued.Add(150 * time.Minute) })
	if !late(leaf) {
		t.Error("2.5h into a 3h cert must refresh")
	}
}
