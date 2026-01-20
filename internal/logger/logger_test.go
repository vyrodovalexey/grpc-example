// Package logger_test provides unit tests for the logger package.
//
// This test file covers all functions in the logger package:
// - InitLogger: Initializes a zap logger with configurable log levels
// - ParseLogLevel: Converts string log levels to zapcore.Level
// - SyncLogger: Flushes buffered log entries
//
// Tests follow the AAA pattern (Arrange, Act, Assert) and use table-driven tests
// for comprehensive coverage of all valid and invalid inputs.
package logger_test

import (
	"errors"
	"testing"

	"github.com/alexey/grpc-example/internal/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// TestParseLogLevel_ValidLevels tests that all valid log levels are correctly parsed.
func TestParseLogLevel_ValidLevels(t *testing.T) {
	tests := []struct {
		name          string
		level         string
		expectedLevel zapcore.Level
	}{
		{
			name:          "debug level",
			level:         "debug",
			expectedLevel: zapcore.DebugLevel,
		},
		{
			name:          "info level",
			level:         "info",
			expectedLevel: zapcore.InfoLevel,
		},
		{
			name:          "warn level",
			level:         "warn",
			expectedLevel: zapcore.WarnLevel,
		},
		{
			name:          "error level",
			level:         "error",
			expectedLevel: zapcore.ErrorLevel,
		},
		{
			name:          "dpanic level",
			level:         "dpanic",
			expectedLevel: zapcore.DPanicLevel,
		},
		{
			name:          "panic level",
			level:         "panic",
			expectedLevel: zapcore.PanicLevel,
		},
		{
			name:          "fatal level",
			level:         "fatal",
			expectedLevel: zapcore.FatalLevel,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			level, err := logger.ParseLogLevel(tt.level)

			// Assert
			require.NoError(t, err)
			assert.Equal(t, tt.expectedLevel, level)
		})
	}
}

// TestParseLogLevel_CaseInsensitivity tests that log level parsing is case-insensitive.
func TestParseLogLevel_CaseInsensitivity(t *testing.T) {
	tests := []struct {
		name          string
		level         string
		expectedLevel zapcore.Level
	}{
		{
			name:          "DEBUG uppercase",
			level:         "DEBUG",
			expectedLevel: zapcore.DebugLevel,
		},
		{
			name:          "Info mixed case",
			level:         "Info",
			expectedLevel: zapcore.InfoLevel,
		},
		{
			name:          "WARN uppercase",
			level:         "WARN",
			expectedLevel: zapcore.WarnLevel,
		},
		{
			name:          "Error mixed case",
			level:         "Error",
			expectedLevel: zapcore.ErrorLevel,
		},
		{
			name:          "WARNING uppercase",
			level:         "WARNING",
			expectedLevel: zapcore.WarnLevel,
		},
		{
			name:          "DPANIC uppercase",
			level:         "DPANIC",
			expectedLevel: zapcore.DPanicLevel,
		},
		{
			name:          "PANIC uppercase",
			level:         "PANIC",
			expectedLevel: zapcore.PanicLevel,
		},
		{
			name:          "FATAL uppercase",
			level:         "FATAL",
			expectedLevel: zapcore.FatalLevel,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			level, err := logger.ParseLogLevel(tt.level)

			// Assert
			require.NoError(t, err)
			assert.Equal(t, tt.expectedLevel, level)
		})
	}
}

// TestParseLogLevel_InvalidLevels tests that invalid log levels return appropriate errors.
func TestParseLogLevel_InvalidLevels(t *testing.T) {
	tests := []struct {
		name  string
		level string
	}{
		{
			name:  "invalid string",
			level: "invalid",
		},
		{
			name:  "trace level not supported",
			level: "trace",
		},
		{
			name:  "verbose level not supported",
			level: "verbose",
		},
		{
			name:  "numeric string",
			level: "123",
		},
		{
			name:  "special characters",
			level: "!@#$%",
		},
		{
			name:  "whitespace only",
			level: "   ",
		},
		{
			name:  "level with whitespace",
			level: " info ",
		},
		{
			name:  "typo in level",
			level: "infoo",
		},
		{
			name:  "partial level name",
			level: "deb",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			level, err := logger.ParseLogLevel(tt.level)

			// Assert
			require.Error(t, err)
			assert.ErrorIs(t, err, logger.ErrInvalidLogLevel)
			// On error, InfoLevel is returned as default
			assert.Equal(t, zapcore.InfoLevel, level)
		})
	}
}

// TestParseLogLevel_EmptyString tests that empty string defaults to info level (zap behavior).
func TestParseLogLevel_EmptyString(t *testing.T) {
	// Act
	level, err := logger.ParseLogLevel("")

	// Assert - empty string is valid in zap and defaults to info level
	require.NoError(t, err)
	assert.Equal(t, zapcore.InfoLevel, level)
}

// TestInitLogger_ValidLevels tests that InitLogger creates a valid logger for all valid levels.
func TestInitLogger_ValidLevels(t *testing.T) {
	tests := []struct {
		name  string
		level string
	}{
		{
			name:  "debug level",
			level: "debug",
		},
		{
			name:  "info level",
			level: "info",
		},
		{
			name:  "warn level",
			level: "warn",
		},
		{
			name:  "error level",
			level: "error",
		},
		{
			name:  "dpanic level",
			level: "dpanic",
		},
		{
			name:  "panic level",
			level: "panic",
		},
		{
			name:  "fatal level",
			level: "fatal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			log, err := logger.InitLogger(tt.level)

			// Assert
			require.NoError(t, err)
			require.NotNil(t, log)

			// Cleanup
			logger.SyncLogger(log)
		})
	}
}

// TestInitLogger_CaseInsensitivity tests that InitLogger handles case-insensitive levels.
func TestInitLogger_CaseInsensitivity(t *testing.T) {
	tests := []struct {
		name  string
		level string
	}{
		{
			name:  "DEBUG uppercase",
			level: "DEBUG",
		},
		{
			name:  "Info mixed case",
			level: "Info",
		},
		{
			name:  "WARN uppercase",
			level: "WARN",
		},
		{
			name:  "Error mixed case",
			level: "Error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			log, err := logger.InitLogger(tt.level)

			// Assert
			require.NoError(t, err)
			require.NotNil(t, log)

			// Cleanup
			logger.SyncLogger(log)
		})
	}
}

// TestInitLogger_InvalidLevels tests that InitLogger returns errors for invalid levels.
func TestInitLogger_InvalidLevels(t *testing.T) {
	tests := []struct {
		name        string
		level       string
		errContains string
	}{
		{
			name:        "invalid string",
			level:       "invalid",
			errContains: "parsing log level",
		},
		{
			name:        "trace level not supported",
			level:       "trace",
			errContains: "parsing log level",
		},
		{
			name:        "verbose level not supported",
			level:       "verbose",
			errContains: "parsing log level",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			log, err := logger.InitLogger(tt.level)

			// Assert
			require.Error(t, err)
			assert.Nil(t, log)
			assert.Contains(t, err.Error(), tt.errContains)
			assert.ErrorIs(t, err, logger.ErrInvalidLogLevel)
		})
	}
}

// TestInitLogger_EmptyString tests that empty string creates a valid logger (defaults to info).
func TestInitLogger_EmptyString(t *testing.T) {
	// Act
	log, err := logger.InitLogger("")

	// Assert - empty string is valid in zap and defaults to info level
	require.NoError(t, err)
	require.NotNil(t, log)
	defer logger.SyncLogger(log)

	// Verify it's configured at info level
	assert.True(t, log.Core().Enabled(zapcore.InfoLevel))
	assert.False(t, log.Core().Enabled(zapcore.DebugLevel))
}

// TestInitLogger_LoggerFunctionality tests that the created logger can actually log.
func TestInitLogger_LoggerFunctionality(t *testing.T) {
	// Arrange
	log, err := logger.InitLogger("debug")
	require.NoError(t, err)
	require.NotNil(t, log)
	defer logger.SyncLogger(log)

	// Act & Assert - these should not panic
	assert.NotPanics(t, func() {
		log.Debug("debug message", zap.String("key", "value"))
	})

	assert.NotPanics(t, func() {
		log.Info("info message", zap.Int("count", 42))
	})

	assert.NotPanics(t, func() {
		log.Warn("warn message", zap.Bool("flag", true))
	})

	assert.NotPanics(t, func() {
		log.Error("error message", zap.Error(errors.New("test error")))
	})
}

// TestInitLogger_LoggerWithFields tests that the logger can handle various field types.
func TestInitLogger_LoggerWithFields(t *testing.T) {
	// Arrange
	log, err := logger.InitLogger("info")
	require.NoError(t, err)
	require.NotNil(t, log)
	defer logger.SyncLogger(log)

	// Act & Assert - test various field types
	assert.NotPanics(t, func() {
		log.Info("message with multiple fields",
			zap.String("string_field", "value"),
			zap.Int("int_field", 123),
			zap.Int64("int64_field", 9223372036854775807),
			zap.Float64("float_field", 3.14159),
			zap.Bool("bool_field", true),
			zap.Error(errors.New("sample error")),
		)
	})
}

// TestInitLogger_NamedLogger tests that the logger can be named.
func TestInitLogger_NamedLogger(t *testing.T) {
	// Arrange
	log, err := logger.InitLogger("info")
	require.NoError(t, err)
	require.NotNil(t, log)
	defer logger.SyncLogger(log)

	// Act
	namedLogger := log.Named("test-component")

	// Assert
	require.NotNil(t, namedLogger)
	assert.NotPanics(t, func() {
		namedLogger.Info("message from named logger")
	})
}

// TestInitLogger_WithOptions tests that the logger can be extended with options.
func TestInitLogger_WithOptions(t *testing.T) {
	// Arrange
	log, err := logger.InitLogger("info")
	require.NoError(t, err)
	require.NotNil(t, log)
	defer logger.SyncLogger(log)

	// Act
	loggerWithCaller := log.WithOptions(zap.AddCaller())

	// Assert
	require.NotNil(t, loggerWithCaller)
	assert.NotPanics(t, func() {
		loggerWithCaller.Info("message with caller info")
	})
}

// TestSyncLogger_NilLogger tests that SyncLogger handles nil logger gracefully.
func TestSyncLogger_NilLogger(t *testing.T) {
	// Act & Assert - should not panic
	assert.NotPanics(t, func() {
		logger.SyncLogger(nil)
	})
}

// TestSyncLogger_ValidLogger tests that SyncLogger works with a valid logger.
func TestSyncLogger_ValidLogger(t *testing.T) {
	// Arrange
	log, err := logger.InitLogger("info")
	require.NoError(t, err)
	require.NotNil(t, log)

	// Act & Assert - should not panic
	assert.NotPanics(t, func() {
		logger.SyncLogger(log)
	})
}

// TestSyncLogger_MultipleCalls tests that SyncLogger can be called multiple times.
func TestSyncLogger_MultipleCalls(t *testing.T) {
	// Arrange
	log, err := logger.InitLogger("info")
	require.NoError(t, err)
	require.NotNil(t, log)

	// Act & Assert - multiple calls should not panic
	assert.NotPanics(t, func() {
		logger.SyncLogger(log)
		logger.SyncLogger(log)
		logger.SyncLogger(log)
	})
}

// TestSyncLogger_AfterLogging tests that SyncLogger works after logging operations.
func TestSyncLogger_AfterLogging(t *testing.T) {
	// Arrange
	log, err := logger.InitLogger("debug")
	require.NoError(t, err)
	require.NotNil(t, log)

	// Log some messages
	log.Debug("debug message")
	log.Info("info message")
	log.Warn("warn message")

	// Act & Assert - sync should not panic
	assert.NotPanics(t, func() {
		logger.SyncLogger(log)
	})
}

// TestSyncLogger_NopLogger tests that SyncLogger works with a nop logger.
func TestSyncLogger_NopLogger(t *testing.T) {
	// Arrange
	log := zap.NewNop()

	// Act & Assert - should not panic
	assert.NotPanics(t, func() {
		logger.SyncLogger(log)
	})
}

// TestErrInvalidLogLevel tests that the error variable is properly defined.
func TestErrInvalidLogLevel(t *testing.T) {
	// Assert
	require.NotNil(t, logger.ErrInvalidLogLevel)
	assert.Contains(t, logger.ErrInvalidLogLevel.Error(), "invalid log level")
}

// TestParseLogLevel_ErrorWrapping tests that errors are properly wrapped.
func TestParseLogLevel_ErrorWrapping(t *testing.T) {
	// Act
	_, err := logger.ParseLogLevel("invalid")

	// Assert
	require.Error(t, err)
	assert.ErrorIs(t, err, logger.ErrInvalidLogLevel)

	// Verify error message contains useful information
	assert.Contains(t, err.Error(), "invalid log level")
}

// TestInitLogger_ErrorWrapping tests that InitLogger errors are properly wrapped.
func TestInitLogger_ErrorWrapping(t *testing.T) {
	// Act
	_, err := logger.InitLogger("invalid")

	// Assert
	require.Error(t, err)
	assert.ErrorIs(t, err, logger.ErrInvalidLogLevel)

	// Verify error message contains the invalid level
	assert.Contains(t, err.Error(), "invalid")
	assert.Contains(t, err.Error(), "parsing log level")
}

// TestInitLogger_LoggerConfiguration tests that the logger is configured correctly.
func TestInitLogger_LoggerConfiguration(t *testing.T) {
	// Arrange & Act
	log, err := logger.InitLogger("info")
	require.NoError(t, err)
	require.NotNil(t, log)
	defer logger.SyncLogger(log)

	// Assert - verify logger core is enabled at the correct level
	assert.True(t, log.Core().Enabled(zapcore.InfoLevel))
	assert.True(t, log.Core().Enabled(zapcore.WarnLevel))
	assert.True(t, log.Core().Enabled(zapcore.ErrorLevel))
	assert.False(t, log.Core().Enabled(zapcore.DebugLevel))
}

// TestInitLogger_DebugLevelConfiguration tests debug level logger configuration.
func TestInitLogger_DebugLevelConfiguration(t *testing.T) {
	// Arrange & Act
	log, err := logger.InitLogger("debug")
	require.NoError(t, err)
	require.NotNil(t, log)
	defer logger.SyncLogger(log)

	// Assert - debug level should enable all levels
	assert.True(t, log.Core().Enabled(zapcore.DebugLevel))
	assert.True(t, log.Core().Enabled(zapcore.InfoLevel))
	assert.True(t, log.Core().Enabled(zapcore.WarnLevel))
	assert.True(t, log.Core().Enabled(zapcore.ErrorLevel))
}

// TestInitLogger_ErrorLevelConfiguration tests error level logger configuration.
func TestInitLogger_ErrorLevelConfiguration(t *testing.T) {
	// Arrange & Act
	log, err := logger.InitLogger("error")
	require.NoError(t, err)
	require.NotNil(t, log)
	defer logger.SyncLogger(log)

	// Assert - error level should only enable error and above
	assert.False(t, log.Core().Enabled(zapcore.DebugLevel))
	assert.False(t, log.Core().Enabled(zapcore.InfoLevel))
	assert.False(t, log.Core().Enabled(zapcore.WarnLevel))
	assert.True(t, log.Core().Enabled(zapcore.ErrorLevel))
}

// TestParseLogLevel_AllZapLevels tests all zapcore levels are correctly mapped.
func TestParseLogLevel_AllZapLevels(t *testing.T) {
	levelMappings := map[string]zapcore.Level{
		"debug":  zapcore.DebugLevel,
		"info":   zapcore.InfoLevel,
		"warn":   zapcore.WarnLevel,
		"error":  zapcore.ErrorLevel,
		"dpanic": zapcore.DPanicLevel,
		"panic":  zapcore.PanicLevel,
		"fatal":  zapcore.FatalLevel,
	}

	for levelStr, expectedLevel := range levelMappings {
		t.Run(levelStr, func(t *testing.T) {
			// Act
			level, err := logger.ParseLogLevel(levelStr)

			// Assert
			require.NoError(t, err)
			assert.Equal(t, expectedLevel, level)
		})
	}
}

// TestInitLogger_SugarLogger tests that the logger can be converted to a sugared logger.
func TestInitLogger_SugarLogger(t *testing.T) {
	// Arrange
	log, err := logger.InitLogger("info")
	require.NoError(t, err)
	require.NotNil(t, log)
	defer logger.SyncLogger(log)

	// Act
	sugar := log.Sugar()

	// Assert
	require.NotNil(t, sugar)
	assert.NotPanics(t, func() {
		sugar.Infof("formatted message: %s", "test")
		sugar.Infow("message with fields", "key", "value", "count", 42)
	})
}

// TestInitLogger_WithFields tests that the logger can have fields added.
func TestInitLogger_WithFields(t *testing.T) {
	// Arrange
	log, err := logger.InitLogger("info")
	require.NoError(t, err)
	require.NotNil(t, log)
	defer logger.SyncLogger(log)

	// Act
	logWithFields := log.With(
		zap.String("service", "test-service"),
		zap.String("version", "1.0.0"),
	)

	// Assert
	require.NotNil(t, logWithFields)
	assert.NotPanics(t, func() {
		logWithFields.Info("message with context fields")
	})
}

// TestInitLogger_Check tests the Check method for conditional logging.
func TestInitLogger_Check(t *testing.T) {
	// Arrange
	log, err := logger.InitLogger("info")
	require.NoError(t, err)
	require.NotNil(t, log)
	defer logger.SyncLogger(log)

	// Act & Assert - Check should return non-nil for enabled levels
	if ce := log.Check(zapcore.InfoLevel, "info message"); ce != nil {
		assert.NotPanics(t, func() {
			ce.Write(zap.String("key", "value"))
		})
	}

	// Check should return nil for disabled levels
	ce := log.Check(zapcore.DebugLevel, "debug message")
	assert.Nil(t, ce)
}

// TestParseLogLevel_WarningAlias tests that "warning" is an alias for "warn".
func TestParseLogLevel_WarningAlias(t *testing.T) {
	// Act
	level, err := logger.ParseLogLevel("warning")

	// Assert
	require.NoError(t, err)
	assert.Equal(t, zapcore.WarnLevel, level)
}

// TestInitLogger_WarningAlias tests that InitLogger accepts "warning" as an alias.
func TestInitLogger_WarningAlias(t *testing.T) {
	// Act
	log, err := logger.InitLogger("warning")

	// Assert
	require.NoError(t, err)
	require.NotNil(t, log)
	defer logger.SyncLogger(log)

	// Verify it's configured at warn level
	assert.True(t, log.Core().Enabled(zapcore.WarnLevel))
	assert.False(t, log.Core().Enabled(zapcore.InfoLevel))
}
