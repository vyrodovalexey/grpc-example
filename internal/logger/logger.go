// Package logger provides structured logging utilities for the gRPC server.
//
// This package wraps the zap logging library to provide a consistent logging
// configuration across the application. It supports configurable log levels
// and outputs structured JSON logs suitable for production environments.
//
// # Usage
//
// Initialize a logger with a specific log level:
//
//	logger, err := logger.InitLogger("info")
//	if err != nil {
//	    log.Fatal("failed to initialize logger:", err)
//	}
//	defer logger.SyncLogger(logger)
//
//	logger.Info("application started")
//
// # Log Levels
//
// Supported log levels are: debug, info, warn, error, dpanic, panic, fatal.
// The default level is "info" if an invalid level is provided.
package logger

import (
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ErrInvalidLogLevel is returned when an invalid log level string is provided.
var ErrInvalidLogLevel = fmt.Errorf("invalid log level")

// InitLogger initializes a zap logger with the specified log level.
//
// The logger is configured for production use with JSON encoding and
// structured output. It includes timestamp, level, caller, and message
// fields in each log entry.
//
// Parameters:
//   - level: The log level string (debug, info, warn, error, dpanic, panic, fatal)
//
// Returns:
//   - *zap.Logger: The configured logger instance
//   - error: An error if the log level is invalid or logger creation fails
//
// Example:
//
//	logger, err := InitLogger("debug")
//	if err != nil {
//	    return fmt.Errorf("failed to initialize logger: %w", err)
//	}
//	defer SyncLogger(logger)
//
//	logger.Info("server starting", zap.String("address", ":8080"))
func InitLogger(level string) (*zap.Logger, error) {
	zapLevel, err := ParseLogLevel(level)
	if err != nil {
		return nil, fmt.Errorf("parsing log level %q: %w", level, err)
	}

	zapConfig := zap.Config{
		Level:       zap.NewAtomicLevelAt(zapLevel),
		Development: false,
		Sampling: &zap.SamplingConfig{
			Initial:    100,
			Thereafter: 100,
		},
		Encoding: "json",
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "timestamp",
			LevelKey:       "level",
			NameKey:        "logger",
			CallerKey:      "caller",
			FunctionKey:    zapcore.OmitKey,
			MessageKey:     "message",
			StacktraceKey:  "stacktrace",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.LowercaseLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.SecondsDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		},
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}

	logger, err := zapConfig.Build()
	if err != nil {
		return nil, fmt.Errorf("building logger: %w", err)
	}

	return logger, nil
}

// ParseLogLevel converts a string log level to zapcore.Level.
//
// Supported levels are: debug, info, warn, error, dpanic, panic, fatal.
// The parsing is case-insensitive.
//
// Parameters:
//   - level: The log level string to parse
//
// Returns:
//   - zapcore.Level: The parsed log level
//   - error: An error if the level string is invalid
//
// Example:
//
//	level, err := ParseLogLevel("warn")
//	if err != nil {
//	    return fmt.Errorf("invalid log level: %w", err)
//	}
//	// level is now zapcore.WarnLevel
func ParseLogLevel(level string) (zapcore.Level, error) {
	var zapLevel zapcore.Level
	if err := zapLevel.UnmarshalText([]byte(level)); err != nil {
		return zapcore.InfoLevel, fmt.Errorf("%w: %s", ErrInvalidLogLevel, err)
	}
	return zapLevel, nil
}

// SyncLogger flushes any buffered log entries.
//
// This function should be called before the application exits to ensure
// all log entries are written. It is typically used with defer.
//
// Note: Sync errors for stdout/stderr are silently ignored on some platforms
// (e.g., macOS) where syncing these file descriptors is not supported.
//
// Parameters:
//   - logger: The zap logger instance to sync
//
// Example:
//
//	logger, _ := InitLogger("info")
//	defer SyncLogger(logger)
//
//	// ... application logic ...
func SyncLogger(logger *zap.Logger) {
	if logger == nil {
		return
	}
	// Ignore sync errors for stdout/stderr on some platforms (e.g., macOS)
	// where syncing these file descriptors returns "inappropriate ioctl for device"
	_ = logger.Sync()
}
