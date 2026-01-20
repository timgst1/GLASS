package policy

import (
	"context"
	"log/slog"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
)

type Manager struct {
	filePath string
	dirPath  string
	baseName string

	log      *slog.Logger
	debounce time.Duration
	interval time.Duration

	current atomic.Value
}

type Options struct {
	Debounce time.Duration
	Interval time.Duration
}

func NewManager(filePath string) *Manager {
	log := slog.Default()
	debounce := 200 * time.Millisecond
	interval := 30 * time.Second

	return &Manager{
		filePath: filePath,
		dirPath:  filepath.Dir(filePath),
		baseName: filepath.Base(filePath),
		log:      log,
		debounce: debounce,
		interval: interval,
	}
}

func (m *Manager) Current() (*Document, bool) {
	v := m.current.Load()
	if v == nil {
		return nil, false
	}
	return v.(*Document), true
}

func (m *Manager) Start(ctx context.Context) error {
	if err := m.reload(); err != nil {
		return err
	}

	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	if err := w.Add(m.dirPath); err != nil {
		_ = w.Close()
		return err
	}

	go func() {
		defer w.Close()

		var timer *time.Timer
		trigger := func() {
			if timer != nil {
				timer.Stop()
			}
			timer = time.AfterFunc(m.debounce, func() {
				if err := m.reload(); err != nil {
					m.log.Error("policy reload failed (keeping last known good)", "err", err)
				} else {
					m.log.Info("policy reloaded")
				}
			})
		}

		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := m.reload(); err != nil {
					m.log.Error("policy periodic reload failed (keeping last known good)", "err", err)
				}
			case ev := <-w.Events:
				//Symlink swap rausfiltern
				name := filepath.Base(ev.Name)
				if name == m.baseName || name == "..data" {
					trigger()
				} else {
					//evtl trigger auch bei allem
				}

			case err := <-w.Errors:
				if err != nil {
					m.log.Error("policy watcher error", "err", err)
				}
			}
		}
	}()

	return nil
}

func (m *Manager) reload() error {
	doc, err := LoadFromFile(m.filePath)
	if err != nil {
		return err
	}
	m.current.Store(doc)
	return nil
}
