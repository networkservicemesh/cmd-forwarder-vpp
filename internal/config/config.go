// Copyright (c) 2025 Nordix and/or its affiliates.
//
// Copyright (c) 2020-2025 Cisco and/or its affiliates.
//
// Copyright (c) 2021-2025 Doc.ai and/or its affiliates.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux
// +build linux

// Package config - contain environment variables used by cmd-forwarder-vpp
package config

import (
	"net"
	"net/url"
	"time"

	"github.com/kelseyhightower/envconfig"

	"github.com/networkservicemesh/cmd-forwarder-vpp/internal/vppinit"
)

// Config - configuration for cmd-forwarder-vpp
type Config struct {
	Name                          string            `default:"forwarder" desc:"Name of Endpoint"`
	Labels                        map[string]string `default:"p2p:true" desc:"Labels related to this forwarder-vpp instance"`
	NSName                        string            `default:"forwarder" desc:"Name of Network Service to Register with Registry"`
	ConnectTo                     url.URL           `default:"unix:///connect.to.socket" desc:"url to connect to" split_words:"true"`
	ListenOn                      url.URL           `default:"unix:///listen.on.socket" desc:"url to listen on" split_words:"true"`
	MaxTokenLifetime              time.Duration     `default:"10m" desc:"maximum lifetime of tokens" split_words:"true"`
	RegistryClientPolicies        []string          `default:"etc/nsm/opa/common/.*.rego,etc/nsm/opa/registry/.*.rego,etc/nsm/opa/client/.*.rego" desc:"paths to files and directories that contain registry client policies" split_words:"true"`
	LogLevel                      string            `default:"INFO" desc:"Log level" split_words:"true"`
	DialTimeout                   time.Duration     `default:"750ms" desc:"Timeout for the dial the next endpoint" split_words:"true"`
	OpenTelemetryEndpoint         string            `default:"otel-collector.observability.svc.cluster.local:4317" desc:"OpenTelemetry Collector Endpoint" split_words:"true"`
	MetricsExportInterval         time.Duration     `default:"10s" desc:"interval between mertics exports" split_words:"true"`
	PprofEnabled                  bool              `default:"false" desc:"is pprof enabled" split_words:"true"`
	PprofListenOn                 string            `default:"localhost:6060" desc:"pprof URL to ListenAndServe" split_words:"true"`
	PrometheusListenOn            string            `default:":8081" desc:"Prometheus URL to ListenAndServe" split_words:"true"`
	PrometheusCAFile              string            `default:"" desc:"Path to the CA file for the Prometheus server (by default the authentication will happen via TLS instead of mTLS)" split_words:"true"`
	PrometheusKeyFile             string            `default:"" desc:"Path to the key file for the Prometheus server (by default it uses a SPIRE generated one)" split_words:"true"`
	PrometheusCertFile            string            `default:"" desc:"Path to the certificate file for the Prometheus server (by default it uses a SPIRE generated one)" split_words:"true"`
	PrometheusMonitorCertificate  bool              `default:"false" desc:"defines whether the custom certificate for Prometheus should be watched for updates" split_words:"true"`
	PrometheusServerHeaderTimeout time.Duration     `default:"5s" desc:"Timeout for how long the Prometheus server waits for complete request headers from the client" split_words:"true"`
	PrometheusMaxBindThreshold    time.Duration     `default:"120s" desc:"Timeout for how long the Prometheus server will try to bind to the same address before giving up" split_words:"true"`

	TunnelIP               net.IP        `desc:"IP to use for tunnels" split_words:"true"`
	VxlanPort              uint16        `default:"0" desc:"VXLAN port to use" split_words:"true"`
	VppAPISocket           string        `default:"/var/run/vpp/external/vpp-api.sock" desc:"filename of socket to connect to existing VPP instance.  If empty a VPP instance is run in forwarder" split_words:"true"`
	VppInit                vppinit.Func  `default:"AF_PACKET" desc:"type of VPP initialization. Must be AF_XDP, AF_PACKET or NONE" split_words:"true"`
	VppInitParams          string        `desc:"Configuration file path containing VPP API parameters for initialization" split_words:"true"`
	VPPMinOperationTimeout time.Duration `default:"2s" desc:"minimum timeout for every vpp operation" split_words:"true"`

	ResourcePollTimeout time.Duration `default:"30s" desc:"device plugin polling timeout" split_words:"true"`
	DevicePluginPath    string        `default:"/var/lib/kubelet/device-plugins/" desc:"path to the device plugin directory" split_words:"true"`
	PodResourcesPath    string        `default:"/var/lib/kubelet/pod-resources/" desc:"path to the pod resources directory" split_words:"true"`
	DeviceSelectorFile  string        `default:"" desc:"config file for device name to label matching" split_words:"true"`
	SRIOVConfigFile     string        `default:"" desc:"PCI resources config path" split_words:"true"`
	PCIDevicesPath      string        `default:"/sys/bus/pci/devices" desc:"path to the PCI devices directory" split_words:"true"`
	PCIDriversPath      string        `default:"/sys/bus/pci/drivers" desc:"path to the PCI drivers directory" split_words:"true"`
	CgroupPath          string        `default:"/host/sys/fs/cgroup/devices" desc:"path to the host cgroup directory" split_words:"true"`
	VFIOPath            string        `default:"/host/dev/vfio" desc:"path to the host VFIO directory" split_words:"true"`
	MechanismPriority   []string      `default:"" desc:"sets priorities for mechanisms" split_words:"true"`
}

// Process reads config from env
func (c *Config) Process() error {
	if err := envconfig.Usage("nsm", c); err != nil {
		return err
	}
	return envconfig.Process("nsm", c)
}
