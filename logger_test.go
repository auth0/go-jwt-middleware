package jwtmiddleware

import (
	"bytes"
	"testing"

	"github.com/rs/zerolog"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestDefaultLogger(t *testing.T) {
	logger := &DefaultLogger{}

	// Test that the logger methods don't panic
	logger.Debugf("debug message: %s", "test")
	logger.Infof("info message: %s", "test")
	logger.Warnf("warn message: %s", "test")
	logger.Errorf("error message: %s", "test")
}

func TestZapLogger(t *testing.T) {
	// Create a zap logger that we can observe
	core, recorded := observer.New(zapcore.InfoLevel)
	zapLogger := zap.New(core)

	// Create our wrapper logger - need to use sugared logger
	logger := NewZapLogger(zapLogger.Sugar())

	// Test each log level
	logger.Debugf("debug message: %s", "test")
	assert.Equal(t, 0, recorded.Len(), "Debug message should not be recorded at Info level")

	logger.Infof("info message: %s", "test")
	assert.Equal(t, 1, recorded.Len(), "Info message should be recorded")
	assert.Equal(t, "info message: test", recorded.All()[0].Message)

	logger.Warnf("warn message: %s", "test")
	assert.Equal(t, 2, recorded.Len(), "Warn message should be recorded")
	assert.Equal(t, "warn message: test", recorded.All()[1].Message)

	logger.Errorf("error message: %s", "test")
	assert.Equal(t, 3, recorded.Len(), "Error message should be recorded")
	assert.Equal(t, "error message: test", recorded.All()[2].Message)
}

func TestZerologLogger(t *testing.T) {
	// Create a buffer to capture log output
	var buf bytes.Buffer
	zerologLogger := zerolog.New(&buf)

	// Create our wrapper logger
	logger := NewZerologLogger(zerologLogger)

	// Test each log level
	logger.Debugf("debug message: %s", "test")
	logger.Infof("info message: %s", "test")
	logger.Warnf("warn message: %s", "test")
	logger.Errorf("error message: %s", "test")

	// Verify logs were written
	logOutput := buf.String()
	assert.Contains(t, logOutput, "debug message: test")
	assert.Contains(t, logOutput, "info message: test")
	assert.Contains(t, logOutput, "warn message: test")
	assert.Contains(t, logOutput, "error message: test")
}

func TestLogrusLogger(t *testing.T) {
	// Create a buffer to capture log output
	var buf bytes.Buffer

	// Create a logrus logger that logs to our buffer
	logrusLogger := logrus.New()
	logrusLogger.Out = &buf
	logrusLogger.Level = logrus.InfoLevel // Default is InfoLevel

	// Create our wrapper logger
	logger := NewLogrusLogger(logrusLogger)

	// Test each log level
	logger.Debugf("debug message: %s", "test")
	logger.Infof("info message: %s", "test")
	logger.Warnf("warn message: %s", "test")
	logger.Errorf("error message: %s", "test")

	// Get the output as a string
	output := buf.String()

	// Debug level should not be logged at InfoLevel
	assert.NotContains(t, output, "debug message: test", "Debug messages should not be logged at Info level")

	// Other levels should be logged
	assert.Contains(t, output, "info message: test")
	assert.Contains(t, output, "warn message: test")
	assert.Contains(t, output, "error message: test")

	// Now set to DebugLevel and test debug messages
	buf.Reset()
	logrusLogger.Level = logrus.DebugLevel

	logger.Debugf("debug message: %s", "test")

	// Now the debug message should be logged
	assert.Contains(t, buf.String(), "debug message: test", "Debug messages should be logged at Debug level")
}
