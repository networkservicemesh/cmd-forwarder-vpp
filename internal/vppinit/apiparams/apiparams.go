// Copyright (c) 2024 Nordix Foundation.
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

// Package apiparams provides parsing factilty for configuration parameters
// file for vpp init
package apiparams

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	yaml "gopkg.in/yaml.v3"

	"github.com/networkservicemesh/govpp/binapi/af_packet"
	"github.com/networkservicemesh/govpp/binapi/af_xdp"
	"github.com/networkservicemesh/sdk/pkg/tools/log"
)

// ConfigYAML contains parameters for various AF types
type ConfigYAML struct {
	AfPacket *AfPacketParams `yaml:"AF_PACKET"`
	AfXdp    *AfXDPParams    `yaml:"AF_XDP"`
}

func (c *ConfigYAML) String() string {
	sb := &strings.Builder{}
	_, _ = sb.WriteString("&{")
	_, _ = sb.WriteString("AF_PACKET:{")
	var strs []string
	strs = append(strs, fmt.Sprintf("%+v", c.AfPacket))
	_, _ = sb.WriteString(strings.Join(strs, " "))
	_, _ = sb.WriteString("},")

	_, _ = sb.WriteString("AF_XDP:{")
	var xdpStrs []string
	xdpStrs = append(xdpStrs, fmt.Sprintf("%+v", c.AfXdp))
	_, _ = sb.WriteString(strings.Join(xdpStrs, " "))
	_, _ = sb.WriteString("},")
	_, _ = sb.WriteString("}")
	return sb.String()
}

// DumpToFile Dump the structure to a given file in yaml format
func (c *ConfigYAML) DumpToFile(filename string) error {
	contents, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(path.Dir(filename), 0o700); err != nil {
		return err
	}
	return os.WriteFile(filename, append([]byte(fileStart), contents...), 0o600)
}

// AfPacketParams contains configuration parameters for AF_PACKET interface
type AfPacketParams struct {
	Mode             af_packet.AfPacketMode  `yaml:"mode"`
	RxFrameSize      uint32                  `yaml:"rxFrameSize"`
	TxFrameSize      uint32                  `yaml:"txFrameSize"`
	RxFramesPerBlock uint32                  `yaml:"rxFramesPerBlock"`
	TxFramesPerBlock uint32                  `yaml:"txFramesPerBlock"`
	NumRxQueues      uint16                  `yaml:"numRxQueues"`
	NumTxQueues      uint16                  `yaml:"numTxQueues"`
	Flags            af_packet.AfPacketFlags `yaml:"flags"`
}

// AfXDPParams contains configuration parameters for AF_XDP interface
type AfXDPParams struct {
	Mode    af_xdp.AfXdpMode `yaml:"mode"`
	RxqSize uint16           `yaml:"rxqSize"`
	TxqSize uint16           `yaml:"txqSize"`
	Flags   af_xdp.AfXdpFlag `yaml:"flags"`
}

// GetDefaults  Get default arguments used by create host interface APIs
func GetDefaults() *ConfigYAML {
	return &ConfigYAML{
		AfPacket: &AfPacketParams{
			Mode:             af_packet.AF_PACKET_API_MODE_ETHERNET,
			RxFrameSize:      10240,
			TxFrameSize:      10240,
			RxFramesPerBlock: 1024,
			TxFramesPerBlock: 1024,
			NumRxQueues:      1,
			NumTxQueues:      0,
			Flags:            af_packet.AF_PACKET_API_FLAG_VERSION_2,
		},
		AfXdp: &AfXDPParams{
			Mode:    af_xdp.AF_XDP_API_MODE_AUTO,
			RxqSize: 8192,
			TxqSize: 8192,
			Flags:   0,
		},
	}
}

// GetAfPacketValues get parameter values for af-packet interface creation
func GetAfPacketValues(ctx context.Context) *AfPacketParams {
	return getConfig(ctx).AfPacket
}

// GetAfXdpValues get parameter values for af-xdp interface creation
func GetAfXdpValues(ctx context.Context) *AfXDPParams {
	return getConfig(ctx).AfXdp
}

func getConfig(ctx context.Context) *ConfigYAML {
	cfg := GetDefaults()
	if _, err := os.Stat(confFilename); os.IsNotExist(err) {
		log.FromContext(ctx).Infof("Configuration file: %q not found, using defaults(%+v)", confFilename, cfg)
		if err = cfg.DumpToFile(confFilename); err != nil {
			log.FromContext(ctx).Warnf("Failed to expose used vppapi AF_ interface default values %+v", err)
		}
		return cfg
	}
	err := ReadConfig(confFilename, cfg)
	if err != nil {
		log.FromContext(ctx).Warnf("Failed to get vppapi AF_ interface default values %+v", err)
		return GetDefaults()
	}
	log.FromContext(ctx).WithField("ReadConfig", confFilename).Infof("unmarshalled Config: %s", cfg)
	return cfg
}

// ReadConfig reads configuration from file
func ReadConfig(configFile string, cfg *ConfigYAML) error {
	bytes, err := os.ReadFile(filepath.Clean(configFile))
	if err != nil {
		return errors.Wrapf(err, "error reading file: %v", configFile)
	}
	if err = yaml.Unmarshal(bytes, cfg); err != nil {
		return errors.Wrapf(err, "error unmarshalling yaml: %s", bytes)
	}
	return nil
}
