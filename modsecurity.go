// Package traefik_modsecurity a modsecurity plugin.
package traefik_modsecurity

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/david-garcia-garcia/traefik-modsecurity/pkg/modsecurity"
	"github.com/david-garcia-garcia/traefik-modsecurity/pkg/reclaim"
)

const keyPrefixPlugin = "plugin:"

// Config is the Traefik plugin configuration Yaegi decodes.
type Config = modsecurity.Config

// CreateConfig returns default plugin configuration.
func CreateConfig() *Config {
	return modsecurity.CreateConfig()
}

// New is the Traefik Yaegi constructor. It reuses one Plugin per name+config and returns a Route.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if next == nil {
		return nil, fmt.Errorf("%s: no next handler provided", name)
	}
	if config == nil {
		return nil, fmt.Errorf("%s: no config provided", name)
	}
	if err := modsecurity.Prepare(config, name); err != nil {
		return nil, err
	}
	return bindPlugin(ctx, next, name, config)
}

// bindPlugin stores or reclaims the Plugin, then ForRoute this next.
func bindPlugin(ctx context.Context, next http.Handler, name string, cfg *Config) (http.Handler, error) {
	stored, err := reclaim.Open(ctx, pluginKey(name, cfg), slog.New(slog.NewTextHandler(io.Discard, nil)), func() (any, error) {
		return modsecurity.New(name, cfg)
	})
	if err != nil {
		return nil, err
	}
	pluginInstance, ok := stored.(*modsecurity.Plugin)
	if !ok {
		return nil, fmt.Errorf("%s: reclaim: want *modsecurity.Plugin, got %T", name, stored)
	}
	return pluginInstance.ForRoute(next)
}

// pluginKey is the process-table key for one Plugin incarnation.
func pluginKey(name string, cfg *Config) string {
	return keyPrefixPlugin + name + ":" + pluginConfigHash(cfg)
}

// pluginConfigHash is JSON+FNV of cfg after Prepare. encoding/json sorts map keys.
func pluginConfigHash(cfg *Config) string {
	b, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Sprintf("%v", cfg)
	}
	h := fnv.New64a()
	_, _ = h.Write(b)
	return strconv.FormatUint(h.Sum64(), 16)
}
