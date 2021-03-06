package windowsiis

import (
	"time"

	"github.com/signalfx/signalfx-agent/internal/core/config"
	"github.com/signalfx/signalfx-agent/internal/monitors"
	"github.com/signalfx/signalfx-agent/internal/monitors/types"
	log "github.com/sirupsen/logrus"
)

const monitorType = "windows-iis"

// MONITOR(windows-iis):
// (Windows Only) This monitor reports metrics for Windows Internet Information Services.
// It is used to drive the Windows IIS dashboard content.
//
// ## Windows Performance Counters
// The underlying source for these metrics are Windows Performance Counters.
// Most of the performance counters that we query in this monitor are actually Gauges
// that represent rates per second and percentages.
//
// This monitor reports the instantaneous values for these Windows Performance Counters.
// This means that in between a collection interval, spikes could occur on the
// Performance Counters.  The best way to mitigate this limitation is to increase
// the reporting interval on this monitor to collect more frequently.
//
// Sample YAML configuration:
//
// ```yaml
// monitors:
//  - type: windows-iis
// ```

var logger = log.WithFields(log.Fields{"monitorType": monitorType})

func init() {
	monitors.Register(monitorType, func() interface{} { return &Monitor{} }, &Config{})
}

// Config for this monitor
type Config struct {
	config.MonitorConfig `singleInstance:"true" acceptsEndpoints:"false"`
	// (Windows Only) Number of seconds that wildcards in counter paths should
	// be expanded and how often to refresh counters from configuration.
	CountersRefreshInterval time.Duration `yaml:"counterRefreshInterval" default:"60s"`
	// (Windows Only) Print out the configurations that match available
	// performance counters.  This used for debugging.
	PrintValid bool `yaml:"printValid"`
}

// Monitor for Utilization
type Monitor struct {
	Output types.Output
	cancel func()
}

// Shutdown stops the metric sync
func (m *Monitor) Shutdown() {
	if m.cancel != nil {
		m.cancel()
	}
}
