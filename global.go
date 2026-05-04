package alan

import (
	"errors"
	"sync/atomic"
)

// ErrNoDefault is returned by Default when no global instance has been set.
var ErrNoDefault = errors.New("alan: no default instance set")

// defaultInstance holds the process-wide Alan singleton.
// It is stored in an atomic.Pointer so Default() is lock-free and
// SetDefault() is safe to call concurrently from any goroutine.
var defaultInstance atomic.Pointer[Alan]

// SetDefault sets the process-wide default Alan instance.
//
// Typical usage: call this once during service startup after New() + Start(),
// then access the instance from any package via Default() / MustDefault().
//
//	a, _ := alan.New(cfg)
//	a.Handle("myapp", handler)
//	_ = a.Start(ctx)
//	alan.SetDefault(a)
//
// Passing nil clears the default.
func SetDefault(a *Alan) {
	defaultInstance.Store(a)
}

// Default returns the process-wide default Alan instance previously registered
// with SetDefault. It returns ErrNoDefault if none has been set.
func Default() (*Alan, error) {
	a := defaultInstance.Load()
	if a == nil {
		return nil, ErrNoDefault
	}
	return a, nil
}

// MustDefault returns the process-wide default Alan instance, panicking if
// none has been set. Use this from code paths where the default is required
// and a missing default is a programmer error (e.g. library helpers invoked
// after service startup).
func MustDefault() *Alan {
	a := defaultInstance.Load()
	if a == nil {
		panic(ErrNoDefault)
	}
	return a
}

// HasDefault reports whether a default instance has been set.
func HasDefault() bool {
	return defaultInstance.Load() != nil
}
