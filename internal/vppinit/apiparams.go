// Copyright (c) 2024 Nordix Foundation.
//
// Copyright (c) 2024 Cisco and/or its affiliates.
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

package vppinit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	yaml "gopkg.in/yaml.v3"

	"github.com/networkservicemesh/govpp/binapi/af_packet"
	"github.com/networkservicemesh/govpp/binapi/af_xdp"
	"github.com/networkservicemesh/sdk/pkg/tools/log"
)

// Parameters contains parameters for various AF types
type Parameters struct {
	AfPacket *AfPacketParams `yaml:"AF_PACKET"`
	AfXdp    *AfXDPParams    `yaml:"AF_XDP"`
}

func (c *Parameters) String() string {
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

func getDefaults() *Parameters {
	return &Parameters{
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

func getConfig(ctx context.Context) *Parameters {
	cfg := getDefaults()
	confFilename := os.Getenv("NSM_VPP_INIT_PARAMS")
	logger := log.FromContext(ctx).WithField("ReadConfig", confFilename)
	if confFilename == "" {
		logger.Infof("Using default VPP init parameters %+v", cfg)
		return cfg
	}
	if _, err := os.Stat(confFilename); os.IsNotExist(err) {
		logger.Infof("Configuration file: %q not found, using default VPP init parameters (%+v)", confFilename, cfg)
		return cfg
	}
	err := readConfig(confFilename, cfg)
	if err != nil {
		defaultCfg := getDefaults()
		logger.Warnf("Failed to read VPP init parameters %+v Using: %+v", err, defaultCfg)
		return defaultCfg
	}
	logger.Infof("Unmarshalled VPP init parameters: %s", cfg)
	return cfg
}

func readConfig(configFile string, cfg *Parameters) error {
	bytes, err := os.ReadFile(filepath.Clean(configFile))
	if err != nil {
		return errors.Wrapf(err, "error reading file: %v", configFile)
	}
	if err = yaml.Unmarshal(bytes, cfg); err != nil {
		return errors.Wrapf(err, "error unmarshalling yaml: %s", bytes)
	}
	return nil
}
