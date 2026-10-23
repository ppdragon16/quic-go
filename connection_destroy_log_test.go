package quic

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/mock/gomock"

	"github.com/daeuniverse/quic-go/internal/utils"
)

// captureLogger records every formatted log line and its level, so a test can
// assert which level a connection lifecycle event was reported at.
type captureLogger struct {
	mu     sync.Mutex
	lines  []string
	prefix string
}

func (l *captureLogger) SetLogLevel(LogLevel)       {}
func (l *captureLogger) SetLogTimeFormat(string)    {}
func (l *captureLogger) Debug() bool                { return false }
func (l *captureLogger) Errorf(f string, a ...any)  { l.record("error", f, a...) }
func (l *captureLogger) Infof(f string, a ...any)   { l.record("info", f, a...) }
func (l *captureLogger) Debugf(f string, a ...any)  { l.record("debug", f, a...) }
func (l *captureLogger) WithPrefix(p string) Logger { return &captureLogger{prefix: p} }
func (l *captureLogger) record(level, f string, a ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, level+": "+fmt.Sprintf(f, a...))
}
func (l *captureLogger) String() string {
	return strings.Join(l.lines, "\n")
}

// TestDestroyNilIsNotError pins the dial-cancellation path: DialAddr cancels
// the context (deadline exceeded) and calls destroy(nil) for every racing
// dial, which used to surface as
//
//	level=error "Destroying connection with error: %!s(<nil>)"
//
// thousands of times per hour while a node is unreachable. A nil destroy must
// report at info level, and no destroy path may format a nil error.
func TestDestroyNilIsNotError(t *testing.T) {
	cap := &captureLogger{}
	orig := utils.DefaultLogger
	utils.DefaultLogger = cap
	defer func() { utils.DefaultLogger = orig }()

	tc := newServerTestConnection(t, nil, nil, false)
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()
	tc.conn.destroy(nil)
	select {
	case <-errChan:
	case <-time.After(time.Second):
		t.Fatal("destroy(nil) did not end the connection run loop")
	}

	got := cap.String()
	if strings.Contains(got, "<nil>") {
		t.Fatalf("a nil error was formatted into a log line:\n%s", got)
	}
	for _, line := range cap.lines {
		if strings.Contains(line, "Destroying") {
			t.Fatalf("destroy(nil) must not log the destroy itself: the dial never completed and the caller already reported why it gave up; got:\n%s", got)
		}
		if strings.Contains(line, "<nil>") {
			t.Fatalf("a nil error was formatted into a log line:\n%s", got)
		}
	}
}
