// Copyright (c) 2020-2022 Cisco and/or its affiliates.
//
// Copyright (c) 2021-2022 Doc.ai and/or its affiliates.
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
	Name                   string            `default:"forwarder" desc:"Name of Endpoint"`
	Labels                 map[string]string `default:"p2p:true" desc:"Labels related to this forwarder-vpp instance"`
	NSName                 string            `default:"forwarder" desc:"Name of Network Service to Register with Registry"`
	ConnectTo              url.URL           `default:"unix:///connect.to.socket" desc:"url to connect to" split_words:"true"`
	ListenOn               url.URL           `default:"unix:///listen.on.socket" desc:"url to listen on" split_words:"true"`
	MaxTokenLifetime       time.Duration     `default:"10m" desc:"maximum lifetime of tokens" split_words:"true"`
	RegistryClientPolicies []string          `default:"etc/nsm/opa/common/.*.rego,etc/nsm/opa/registry/.*.rego,etc/nsm/opa/client/.*.rego" desc:"paths to files and directories that contain registry client policies" split_words:"true"`
	LogLevel               string            `default:"INFO" desc:"Log level" split_words:"true"`
	DialTimeout            time.Duration     `default:"100ms" desc:"Timeout for the dial the next endpoint" split_words:"true"`
	OpenTelemetryEndpoint  string            `default:"otel-collector.observability.svc.cluster.local:4317" desc:"OpenTelemetry Collector Endpoint"`

	TunnelIP     net.IP       `desc:"IP to use for tunnels" split_words:"true"`
	VxlanPort    uint16       `default:"0" desc:"VXLAN port to use" split_words:"true"`
	VppAPISocket string       `default:"/var/run/vpp/external/vpp-api.sock" desc:"filename of socket to connect to existing VPP instance.  If empty a VPP instance is run in forwarder" split_words:"true"`
	VppInit      vppinit.Func `default:"NONE" desc:"type of VPP initialization. Must be NONE or AF_PACKET" split_words:"true"`

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
