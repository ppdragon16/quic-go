// Package pool provides injectable buffer allocation hooks for the quic-go
// wire package. By default, GetBuffer falls back to make() and PutBuffer is a
// no-op. Callers may replace them to share a global buffer pool:
//
//	quicpool.GetBuffer = pool.GetBuffer
//	quicpool.PutBuffer = pool.PutBuffer
package pool

// GetBuffer allocates a []byte of the given size. The default implementation
// falls back to make([]byte, size). Replace to inject an external pool.
var GetBuffer func(int) []byte = func(size int) []byte { return make([]byte, size) }

// PutBuffer returns a []byte previously obtained from GetBuffer. The default
// implementation is a no-op (the buffer is left for GC). Replace to inject
// an external pool.
var PutBuffer func([]byte) = func([]byte) {}
