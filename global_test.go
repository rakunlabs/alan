package alan

import (
	"errors"
	"sync"
	"testing"
)

func TestDefault_NotSet(t *testing.T) {
	// Ensure clean state
	SetDefault(nil)

	if HasDefault() {
		t.Fatal("expected HasDefault()=false when no default set")
	}

	a, err := Default()
	if !errors.Is(err, ErrNoDefault) {
		t.Fatalf("expected ErrNoDefault, got %v", err)
	}
	if a != nil {
		t.Fatalf("expected nil instance, got %v", a)
	}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected MustDefault() to panic when no default set")
		}
	}()
	_ = MustDefault()
}

func TestDefault_SetAndGet(t *testing.T) {
	defer SetDefault(nil) // cleanup

	inst, err := New(Config{Port: 15001})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	SetDefault(inst)

	if !HasDefault() {
		t.Fatal("expected HasDefault()=true after SetDefault")
	}

	got, err := Default()
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	if got != inst {
		t.Fatalf("Default() returned different instance")
	}

	if MustDefault() != inst {
		t.Fatalf("MustDefault() returned different instance")
	}
}

func TestDefault_Clear(t *testing.T) {
	inst, err := New(Config{Port: 15002})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	SetDefault(inst)
	SetDefault(nil)

	if HasDefault() {
		t.Fatal("expected HasDefault()=false after clearing")
	}
}

func TestDefault_ConcurrentAccess(t *testing.T) {
	defer SetDefault(nil)

	inst, err := New(Config{Port: 15003})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	SetDefault(inst)

	const n = 100
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			if got, err := Default(); err != nil || got != inst {
				t.Errorf("concurrent Default mismatch: got=%v err=%v", got, err)
			}
		}()
	}
	wg.Wait()
}
