package logging

import (
	"testing"

	"go.uber.org/zap/zapcore"
)

func TestNewJSON(t *testing.T) {
	logger, err := New("info", "json")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = logger.Sync() }()
	if logger.Core().Enabled(zapcore.DebugLevel) {
		t.Error("debug should be disabled at info level")
	}
	if !logger.Core().Enabled(zapcore.InfoLevel) {
		t.Error("info should be enabled")
	}
}

func TestNewConsoleDebug(t *testing.T) {
	logger, err := New("debug", "console")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = logger.Sync() }()
	if !logger.Core().Enabled(zapcore.DebugLevel) {
		t.Error("debug should be enabled")
	}
}

func TestNewErrors(t *testing.T) {
	if _, err := New("nope", "json"); err == nil {
		t.Error("expected error for bad level")
	}
	if _, err := New("info", "xml"); err == nil {
		t.Error("expected error for bad format")
	}
}
