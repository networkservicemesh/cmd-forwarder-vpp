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

package tests

import (
	"context"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
	yaml "gopkg.in/yaml.v3"

	"github.com/networkservicemesh/govpp/binapi/af_packet"

	"github.com/networkservicemesh/cmd-forwarder-vpp/internal/vppinit"
)

const (
	configFilePath = "/var/lib/networkservicemesh/vppapi-hostint-args.yaml"
)

type SomeValuesType struct {
	AfPacket *SomeAfPacketParams `yaml:"AF_PACKET"`
	AfXdp    *SomeAfXDPParams    `yaml:"AF_XDP"`
}

type SomeAfPacketParams struct {
	RxFrameSize      uint32 `yaml:"rxFrameSize"`
	RxFramesPerBlock uint32 `yaml:"rxFramesPerBlock"`
}

type SomeAfXDPParams struct {
	RxqSize uint16 `yaml:"rxqSize"`
}

var someValues = &SomeValuesType{
	AfPacket: &SomeAfPacketParams{
		RxFrameSize:      20480,
		RxFramesPerBlock: 2048,
	},
	AfXdp: &SomeAfXDPParams{
		RxqSize: 16384,
	},
}

func (c *SomeValuesType) DumpToFile(filename string) error {
	contents, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(path.Dir(filename), 0o700); err != nil {
		return err
	}
	return os.WriteFile(filename, contents, 0o600)
}

func TestDefaults(t *testing.T) {
	packetValues := vppinit.GetAfPacketValues(context.Background())
	require.Equal(t, &vppinit.AfPacketParams{
		Mode:             af_packet.AF_PACKET_API_MODE_ETHERNET,
		Flags:            af_packet.AF_PACKET_API_FLAG_VERSION_2,
		RxFrameSize:      10240,
		TxFrameSize:      10240,
		RxFramesPerBlock: 1024,
		TxFramesPerBlock: 1024,
		NumRxQueues:      1,
		NumTxQueues:      0,
	},
		packetValues)

	xdpValues := vppinit.GetAfXdpValues(context.Background())
	require.Equal(t, &vppinit.AfXDPParams{
		Mode:    0,
		RxqSize: 8192,
		TxqSize: 8192,
		Flags:   0,
	},
		xdpValues)
}

func TestSomeValuesSet(t *testing.T) {
	_ = os.Setenv("NSM_VPP_INIT_PARAMS", configFilePath)
	err := someValues.DumpToFile(configFilePath)
	require.NoError(t, err)
	defer func() {
		if errRem := os.RemoveAll(configFilePath); errRem != nil {
			t.Fatalf("no file generated or the generated file cannot removed")
		}
	}()

	packetValues := vppinit.GetAfPacketValues(context.Background())
	require.Equal(t, &vppinit.AfPacketParams{
		Mode:             af_packet.AF_PACKET_API_MODE_ETHERNET,
		Flags:            af_packet.AF_PACKET_API_FLAG_VERSION_2,
		RxFrameSize:      20480,
		TxFrameSize:      10240,
		RxFramesPerBlock: 2048,
		TxFramesPerBlock: 1024,
		NumRxQueues:      1,
		NumTxQueues:      0,
	},
		packetValues)

	xdpValues := vppinit.GetAfXdpValues(context.Background())
	require.Equal(t, &vppinit.AfXDPParams{
		Mode:    0,
		RxqSize: 16384,
		TxqSize: 8192,
		Flags:   0,
	},
		xdpValues)
}
