package utils

import (
	"runtime"
	"testing"
)

type pooledObj struct{ v int }

func TestPoolSurvivesGC(t *testing.T) {
	p := NewPool(func() *pooledObj { return &pooledObj{} }, 16)
	o := p.Get()
	o.v = 42
	p.Put(o)

	runtime.GC()
	runtime.GC()

	if got := p.Get(); got != o {
		t.Fatalf("pool did not survive GC: got %p, want the recycled %p", got, o)
	}
}

func TestPoolIsBounded(t *testing.T) {
	const max = 8
	p := NewPool(func() *pooledObj { return &pooledObj{} }, max)
	for i := 0; i < max*3; i++ {
		p.Put(&pooledObj{})
	}
	if got := p.Len(); got != max {
		t.Fatalf("pool retained %d values, want the bound %d", got, max)
	}
	if p.Get() == nil {
		t.Fatal("Get returned nil after over-Put")
	}
}

func TestPoolEmptyUsesNewFn(t *testing.T) {
	p := NewPool(func() *pooledObj { return &pooledObj{v: 7} }, 4)
	if got := p.Get(); got == nil || got.v != 7 {
		t.Fatalf("empty pool did not use newFn: %+v", got)
	}
}

func TestPoolWorksForSlices(t *testing.T) {
	p := NewPool(func() []int { return make([]int, 0, 4) }, 4)
	s := p.Get()
	s = append(s, 1, 2, 3)
	p.Put(s[:0])
	got := p.Get()
	if cap(got) != 4 {
		t.Fatalf("pooled slice lost its capacity: cap=%d, want 4", cap(got))
	}
}
