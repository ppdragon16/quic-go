package quic

import "github.com/daeuniverse/quic-go/internal/utils"

// Logger is the logging interface used by quic-go.
// Implementations can be injected via SetLogger to route quic-go logs
// through an external logging framework (e.g. logrus).
type Logger = utils.Logger

// LogLevel controls the verbosity of quic-go logging.
type LogLevel = utils.LogLevel

const (
	LogLevelNothing LogLevel = utils.LogLevelNothing
	LogLevelError   LogLevel = utils.LogLevelError
	LogLevelInfo    LogLevel = utils.LogLevelInfo
	LogLevelDebug   LogLevel = utils.LogLevelDebug
)

// SetLogger replaces the global logger used by quic-go.
// The default logger reads the QUIC_GO_LOG_LEVEL env var and writes to stderr.
func SetLogger(l Logger) {
	utils.DefaultLogger = l
}
