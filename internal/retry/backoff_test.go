// Package retry_test provides unit tests for the retry package.
package retry_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/vyrodovalexey/grpc-example/internal/retry"
)

func TestDefaultConfig(t *testing.T) {
	// Act
	cfg := retry.DefaultConfig()

	// Assert
	assert.Equal(t, retry.DefaultMaxRetries, cfg.MaxRetries)
	assert.Equal(t, retry.DefaultBaseDelay, cfg.BaseDelay)
	assert.Equal(t, retry.DefaultMaxDelay, cfg.MaxDelay)
	assert.Equal(t, retry.DefaultJitterFraction, cfg.JitterFraction)
}

func TestDefaultConstants(t *testing.T) {
	// Assert
	assert.Equal(t, 5, retry.DefaultMaxRetries)
	assert.Equal(t, 500*time.Millisecond, retry.DefaultBaseDelay)
	assert.Equal(t, 30*time.Second, retry.DefaultMaxDelay)
	assert.Equal(t, 0.25, retry.DefaultJitterFraction)
}

func TestConfig_CalculateDelay_NoJitter(t *testing.T) {
	tests := []struct {
		name    string
		cfg     retry.Config
		attempt int
		want    time.Duration
	}{
		{
			name: "attempt 0 - base delay",
			cfg: retry.Config{
				BaseDelay:      100 * time.Millisecond,
				MaxDelay:       10 * time.Second,
				JitterFraction: 0, // No jitter for deterministic tests.
			},
			attempt: 0,
			want:    100 * time.Millisecond, // 100ms * 2^0 = 100ms
		},
		{
			name: "attempt 1 - doubled",
			cfg: retry.Config{
				BaseDelay:      100 * time.Millisecond,
				MaxDelay:       10 * time.Second,
				JitterFraction: 0,
			},
			attempt: 1,
			want:    200 * time.Millisecond, // 100ms * 2^1 = 200ms
		},
		{
			name: "attempt 2 - quadrupled",
			cfg: retry.Config{
				BaseDelay:      100 * time.Millisecond,
				MaxDelay:       10 * time.Second,
				JitterFraction: 0,
			},
			attempt: 2,
			want:    400 * time.Millisecond, // 100ms * 2^2 = 400ms
		},
		{
			name: "attempt 3 - 8x",
			cfg: retry.Config{
				BaseDelay:      100 * time.Millisecond,
				MaxDelay:       10 * time.Second,
				JitterFraction: 0,
			},
			attempt: 3,
			want:    800 * time.Millisecond, // 100ms * 2^3 = 800ms
		},
		{
			name: "delay capped at max",
			cfg: retry.Config{
				BaseDelay:      1 * time.Second,
				MaxDelay:       5 * time.Second,
				JitterFraction: 0,
			},
			attempt: 10, // 1s * 2^10 = 1024s, capped at 5s
			want:    5 * time.Second,
		},
		{
			name: "delay exactly at max",
			cfg: retry.Config{
				BaseDelay:      500 * time.Millisecond,
				MaxDelay:       2 * time.Second,
				JitterFraction: 0,
			},
			attempt: 2, // 500ms * 2^2 = 2s, exactly at max
			want:    2 * time.Second,
		},
		{
			name: "delay exceeds max by small amount",
			cfg: retry.Config{
				BaseDelay:      500 * time.Millisecond,
				MaxDelay:       1500 * time.Millisecond,
				JitterFraction: 0,
			},
			attempt: 2, // 500ms * 2^2 = 2000ms, capped at 1500ms
			want:    1500 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			delay := tt.cfg.CalculateDelay(tt.attempt)

			// Assert
			assert.Equal(t, tt.want, delay)
		})
	}
}

func TestConfig_CalculateDelay_WithJitter(t *testing.T) {
	tests := []struct {
		name    string
		cfg     retry.Config
		attempt int
		wantMin time.Duration
		wantMax time.Duration
	}{
		{
			name: "attempt 0 with default jitter (±25%)",
			cfg: retry.Config{
				BaseDelay:      100 * time.Millisecond,
				MaxDelay:       10 * time.Second,
				JitterFraction: 0.25,
			},
			attempt: 0,
			wantMin: 75 * time.Millisecond,  // 100ms - 25%
			wantMax: 125 * time.Millisecond, // 100ms + 25%
		},
		{
			name: "attempt 2 with default jitter (±25%)",
			cfg: retry.Config{
				BaseDelay:      100 * time.Millisecond,
				MaxDelay:       10 * time.Second,
				JitterFraction: 0.25,
			},
			attempt: 2,
			wantMin: 300 * time.Millisecond, // 400ms - 25%
			wantMax: 500 * time.Millisecond, // 400ms + 25%
		},
		{
			name:    "default config attempt 0",
			cfg:     retry.DefaultConfig(),
			attempt: 0,
			wantMin: 375 * time.Millisecond, // 500ms - 25%
			wantMax: 625 * time.Millisecond, // 500ms + 25%
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Run multiple times to verify jitter is within bounds.
			for range 100 {
				delay := tt.cfg.CalculateDelay(tt.attempt)
				assert.GreaterOrEqual(t, delay, tt.wantMin,
					"delay %v should be >= %v", delay, tt.wantMin)
				assert.LessOrEqual(t, delay, tt.wantMax,
					"delay %v should be <= %v", delay, tt.wantMax)
			}
		})
	}
}

func TestConfig_CalculateDelay_JitterProducesVariation(t *testing.T) {
	cfg := retry.Config{
		BaseDelay:      1 * time.Second,
		MaxDelay:       30 * time.Second,
		JitterFraction: 0.25,
	}

	// Collect delays and verify they are not all identical.
	seen := make(map[time.Duration]bool)
	for range 50 {
		delay := cfg.CalculateDelay(0)
		seen[delay] = true
	}

	// With jitter, we should see multiple distinct values.
	assert.Greater(t, len(seen), 1, "jitter should produce variation in delays")
}

func TestConfig_CalculateDelay_DelayNeverNegative(t *testing.T) {
	cfg := retry.Config{
		BaseDelay:      1 * time.Millisecond,
		MaxDelay:       10 * time.Second,
		JitterFraction: 0.25,
	}

	for range 100 {
		delay := cfg.CalculateDelay(0)
		assert.GreaterOrEqual(t, delay, time.Duration(0), "delay should never be negative")
	}
}

func TestDo_SuccessOnFirstAttempt(t *testing.T) {
	// Arrange
	cfg := retry.Config{
		MaxRetries: 3,
		BaseDelay:  10 * time.Millisecond,
		MaxDelay:   100 * time.Millisecond,
	}
	logger := zap.NewNop()
	callCount := 0

	// Act
	err := retry.Do(context.Background(), cfg, logger, "test operation", func() error {
		callCount++
		return nil
	})

	// Assert
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)
}

func TestDo_SuccessAfterRetries(t *testing.T) {
	// Arrange
	cfg := retry.Config{
		MaxRetries: 5,
		BaseDelay:  10 * time.Millisecond,
		MaxDelay:   100 * time.Millisecond,
	}
	logger := zap.NewNop()
	callCount := 0

	// Act
	err := retry.Do(context.Background(), cfg, logger, "test operation", func() error {
		callCount++
		if callCount < 3 {
			return fmt.Errorf("attempt %d failed", callCount)
		}
		return nil
	})

	// Assert
	require.NoError(t, err)
	assert.Equal(t, 3, callCount)
}

func TestDo_AllAttemptsFail(t *testing.T) {
	// Arrange
	cfg := retry.Config{
		MaxRetries: 3,
		BaseDelay:  10 * time.Millisecond,
		MaxDelay:   50 * time.Millisecond,
	}
	logger := zap.NewNop()
	callCount := 0

	// Act
	err := retry.Do(context.Background(), cfg, logger, "test operation", func() error {
		callCount++
		return fmt.Errorf("persistent error %d", callCount)
	})

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "test operation failed after 3 attempts")
	assert.Contains(t, err.Error(), "persistent error 3")
	assert.Equal(t, 3, callCount)
}

func TestDo_ContextCancelledBeforeFirstAttempt(t *testing.T) {
	// Arrange
	cfg := retry.Config{
		MaxRetries: 5,
		BaseDelay:  10 * time.Millisecond,
		MaxDelay:   100 * time.Millisecond,
	}
	logger := zap.NewNop()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	callCount := 0

	// Act
	err := retry.Do(ctx, cfg, logger, "test operation", func() error {
		callCount++
		return nil
	})

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context cancelled during test operation")
	assert.Equal(t, 0, callCount)
}

func TestDo_ContextCancelledDuringRetryWait(t *testing.T) {
	// Arrange
	cfg := retry.Config{
		MaxRetries: 5,
		BaseDelay:  1 * time.Second, // Long delay to ensure context cancels during wait
		MaxDelay:   5 * time.Second,
	}
	logger := zap.NewNop()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	callCount := 0

	// Act
	err := retry.Do(ctx, cfg, logger, "test operation", func() error {
		callCount++
		return fmt.Errorf("always fails")
	})

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context cancelled during retry wait")
	assert.Equal(t, 1, callCount)
}

func TestDo_SingleRetry(t *testing.T) {
	// Arrange
	cfg := retry.Config{
		MaxRetries: 1,
		BaseDelay:  10 * time.Millisecond,
		MaxDelay:   100 * time.Millisecond,
	}
	logger := zap.NewNop()
	callCount := 0

	// Act
	err := retry.Do(context.Background(), cfg, logger, "single retry", func() error {
		callCount++
		return fmt.Errorf("always fails")
	})

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "single retry failed after 1 attempts")
	assert.Equal(t, 1, callCount)
}

func TestDo_OperationNameInError(t *testing.T) {
	tests := []struct {
		name      string
		operation string
	}{
		{
			name:      "vault PKI request",
			operation: "vault PKI request",
		},
		{
			name:      "OIDC discovery",
			operation: "OIDC discovery",
		},
		{
			name:      "vault CA retrieval",
			operation: "vault CA retrieval",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			cfg := retry.Config{
				MaxRetries: 1,
				BaseDelay:  10 * time.Millisecond,
				MaxDelay:   50 * time.Millisecond,
			}
			logger := zap.NewNop()

			// Act
			err := retry.Do(context.Background(), cfg, logger, tt.operation, func() error {
				return fmt.Errorf("failed")
			})

			// Assert
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.operation)
		})
	}
}

func TestDo_ContextCancelledErrorMessage(t *testing.T) {
	// Arrange
	cfg := retry.Config{
		MaxRetries: 5,
		BaseDelay:  10 * time.Millisecond,
		MaxDelay:   100 * time.Millisecond,
	}
	logger := zap.NewNop()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Act
	err := retry.Do(ctx, cfg, logger, "my operation", func() error {
		return nil
	})

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context cancelled during my operation")
	assert.ErrorIs(t, err, context.Canceled)
}

func TestDo_WrapsLastError(t *testing.T) {
	// Arrange
	cfg := retry.Config{
		MaxRetries: 2,
		BaseDelay:  10 * time.Millisecond,
		MaxDelay:   50 * time.Millisecond,
	}
	logger := zap.NewNop()
	callCount := 0

	// Act
	err := retry.Do(context.Background(), cfg, logger, "test op", func() error {
		callCount++
		return fmt.Errorf("error on attempt %d", callCount)
	})

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "test op failed after 2 attempts")
	assert.Contains(t, err.Error(), "error on attempt 2") // Last error is wrapped
}
