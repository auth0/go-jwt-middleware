package jwtmiddleware

import (
	"log"

	"github.com/rs/zerolog"
	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
)

// Logger is a generic logging interface for the middleware.
type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// LogLevel represents the level of logging.
type LogLevel int

const (
	LogLevelNone LogLevel = iota
	LogLevelError
	LogLevelWarn
	LogLevelInfo
	LogLevelDebug
)

// DefaultLogger is a simple logger that uses the standard library log package.
type DefaultLogger struct{}

func (l *DefaultLogger) Debugf(format string, args ...interface{}) {
	log.Printf("DEBUG: "+format, args...)
}
func (l *DefaultLogger) Infof(format string, args ...interface{}) {
	log.Printf("INFO: "+format, args...)
}
func (l *DefaultLogger) Warnf(format string, args ...interface{}) {
	log.Printf("WARN: "+format, args...)
}
func (l *DefaultLogger) Errorf(format string, args ...interface{}) {
	log.Printf("ERROR: "+format, args...)
}

// NewZapLogger returns a Logger adapter for zap.SugaredLogger.
func NewZapLogger(l *zap.SugaredLogger) Logger {
	return &zapLoggerAdapter{l}
}

type zapLoggerAdapter struct{ l *zap.SugaredLogger }

func (z *zapLoggerAdapter) Debugf(format string, args ...interface{}) { z.l.Debugf(format, args...) }
func (z *zapLoggerAdapter) Infof(format string, args ...interface{})  { z.l.Infof(format, args...) }
func (z *zapLoggerAdapter) Warnf(format string, args ...interface{})  { z.l.Warnf(format, args...) }
func (z *zapLoggerAdapter) Errorf(format string, args ...interface{}) { z.l.Errorf(format, args...) }

// NewZerologLogger returns a Logger adapter for zerolog.Logger.
func NewZerologLogger(l zerolog.Logger) Logger {
	return &zerologLoggerAdapter{l}
}

type zerologLoggerAdapter struct{ l zerolog.Logger }

func (z *zerologLoggerAdapter) Debugf(format string, args ...interface{}) {
	z.l.Debug().Msgf(format, args...)
}
func (z *zerologLoggerAdapter) Infof(format string, args ...interface{}) {
	z.l.Info().Msgf(format, args...)
}
func (z *zerologLoggerAdapter) Warnf(format string, args ...interface{}) {
	z.l.Warn().Msgf(format, args...)
}
func (z *zerologLoggerAdapter) Errorf(format string, args ...interface{}) {
	z.l.Error().Msgf(format, args...)
}

// NewLogrusLogger returns a Logger adapter for logrus.FieldLogger.
func NewLogrusLogger(l logrus.FieldLogger) Logger {
	return &logrusLoggerAdapter{l}
}

type logrusLoggerAdapter struct{ l logrus.FieldLogger }

func (l *logrusLoggerAdapter) Debugf(format string, args ...interface{}) { l.l.Debugf(format, args...) }
func (l *logrusLoggerAdapter) Infof(format string, args ...interface{})  { l.l.Infof(format, args...) }
func (l *logrusLoggerAdapter) Warnf(format string, args ...interface{})  { l.l.Warnf(format, args...) }
func (l *logrusLoggerAdapter) Errorf(format string, args ...interface{}) { l.l.Errorf(format, args...) }
