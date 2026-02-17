// Package retry provides exponential backoff retry utilities.
package retry

import (
	"context"
	"fmt"
	"math"
	"math/rand/v2"
	"time"

	"go.uber.org/zap"
)

const (
	// DefaultMaxRetries is the default maximum number of retry attempts.
	DefaultMaxRetries = 5
	// DefaultBaseDelay is the default base delay for exponential backoff.
	DefaultBaseDelay = 500 * time.Millisecond
	// DefaultMaxDelay is the default maximum delay cap.
	DefaultMaxDelay = 30 * time.Second
	// DefaultJitterFraction is the default jitter fraction (±25% of delay).
	DefaultJitterFraction = 0.25
)

// Config holds configuration for exponential backoff retry.
type Config struct {
	MaxRetries     int
	BaseDelay      time.Duration
	MaxDelay       time.Duration
	JitterFraction float64 // Fraction of delay to use as jitter range (e.g. 0.25 = ±25%).
}

// DefaultConfig returns the default retry configuration.
func DefaultConfig() Config {
	return Config{
		MaxRetries:     DefaultMaxRetries,
		BaseDelay:      DefaultBaseDelay,
		MaxDelay:       DefaultMaxDelay,
		JitterFraction: DefaultJitterFraction,
	}
}

// CalculateDelay calculates exponential backoff delay with jitter for the given attempt.
// Jitter is applied as ±JitterFraction of the computed delay to prevent thundering herd effects.
func (c Config) CalculateDelay(attempt int) time.Duration {
	delay := c.BaseDelay * time.Duration(math.Pow(2, float64(attempt)))
	if delay > c.MaxDelay {
		delay = c.MaxDelay
	}

	// Apply jitter: delay ± (delay * JitterFraction).
	if c.JitterFraction > 0 {
		jitterRange := float64(delay) * c.JitterFraction
		// rand.Float64() returns [0.0, 1.0), scale to [-1.0, 1.0).
		//nolint:gosec // jitter needs no crypto rand
		jitter := time.Duration((rand.Float64()*2 - 1) * jitterRange)
		delay += jitter
		if delay < 0 {
			delay = 0
		}
	}

	return delay
}

// Do executes fn with exponential backoff retries.
// It logs warnings on each failed attempt using the provided logger.
// Returns the last error if all attempts fail.
func Do(ctx context.Context, cfg Config, logger *zap.Logger, operation string, fn func() error) error {
	var err error

	for attempt := range cfg.MaxRetries {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled during %s: %w", operation, ctx.Err())
		default:
		}

		if err = fn(); err == nil {
			return nil
		}

		delay := cfg.CalculateDelay(attempt)
		logger.Warn(operation+" failed, retrying",
			zap.Int("attempt", attempt+1),
			zap.Duration("retry_delay", delay),
			zap.Error(err),
		)

		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled during retry wait: %w", ctx.Err())
		case <-time.After(delay):
		}
	}

	return fmt.Errorf("%s failed after %d attempts: %w", operation, cfg.MaxRetries, err)
}
