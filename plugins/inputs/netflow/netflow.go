package netflow

import (
	"github.com/influxdata/telegraf/filter"
	"github.com/influxdata/telegraf/plugins/inputs/system"
)

type NetFlowStats struct {
	filter filter.Filter
	ps     system.PS

	Version  int
	Endpoint string
}

func (_ *NetFlowStats) Description() string {
	return "Read fata from NetFlow source"
}

var netFlowSampleConfig = `
  ## Which version of NetFlow is delivered to this endpoint.
  ## Supported are v1, v5 and v9 flows
  # version = 5
  ##
  ## Address of endpoint accepting incoming transmission
  ##
  # endpoint = "udp://localhost:2055"
  ##
`

func (_ *NetFlowStats) SampleConfig() string {
	return netFlowSampleConfig
}
