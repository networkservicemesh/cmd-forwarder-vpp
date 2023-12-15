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

package tests

import (
	"bytes"
	"context"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	yaml "gopkg.in/yaml.v3"

	"github.com/networkservicemesh/govpp/binapi/af_packet"
	"github.com/networkservicemesh/govpp/binapi/af_xdp"

	"github.com/networkservicemesh/cmd-forwarder-vpp/internal/vppinit/apiparams"
)

const (
	configFilePath    = "/var/lib/networkservicemesh/vppapi-hostint-args.yaml"
	exampleFileName   = "example-config/example-hostint-args.yaml"
	defaultFileName   = "example-config/default.yaml"
	generatedFileName = "default-generated.yaml"
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

func TestReadConfigFile(t *testing.T) {
	cfg := &apiparams.ConfigYAML{}
	err := apiparams.ReadConfig(exampleFileName, cfg)
	require.NoError(t, err)
	require.Equal(t, &apiparams.ConfigYAML{
		AfPacket: &apiparams.AfPacketParams{
			Mode:             af_packet.AF_PACKET_API_MODE_ETHERNET,
			Flags:            af_packet.AF_PACKET_API_FLAG_CKSUM_GSO,
			RxFrameSize:      2048,
			TxFrameSize:      10240,
			RxFramesPerBlock: 32,
			TxFramesPerBlock: 1024,
			NumRxQueues:      1,
			NumTxQueues:      1,
		},
		AfXdp: &apiparams.AfXDPParams{
			Mode:    af_xdp.AF_XDP_API_MODE_COPY,
			RxqSize: 8192,
			TxqSize: 8192,
			Flags:   af_xdp.AF_XDP_API_FLAGS_NO_SYSCALL_LOCK,
		},
	}, cfg)
}

func TestDumpDefaults(t *testing.T) {
	cfg := apiparams.GetDefaults()
	err := cfg.DumpToFile(generatedFileName)
	require.NoError(t, err)
	defer func() {
		if errRem := os.RemoveAll(generatedFileName); errRem != nil {
			t.Fatalf("no file generated or the generated file cannot removed")
		}
	}()

	generated, err := os.ReadFile(filepath.Clean(generatedFileName))
	require.NoError(t, err)
	want, err := os.ReadFile(filepath.Clean(defaultFileName))
	require.NoError(t, err)

	if !bytes.Equal(generated, want) {
		t.Fatalf("%s: have:\n%s\nwant:\n%s\n%+v", generatedFileName, generated,
			want, cfg)
	}
}

func TestSomeValuesSet(t *testing.T) {
	err := someValues.DumpToFile(configFilePath)
	require.NoError(t, err)
	defer func() {
		if errRem := os.RemoveAll(configFilePath); errRem != nil {
			t.Fatalf("no file generated or the generated file cannot removed")
		}
	}()

	packetValues := apiparams.GetAfPacketValues(context.Background())
	require.Equal(t, &apiparams.AfPacketParams{
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

	xdpValues := apiparams.GetAfXdpValues(context.Background())
	require.Equal(t, &apiparams.AfXDPParams{
		Mode:    0,
		RxqSize: 16384,
		TxqSize: 8192,
		Flags:   0,
	},
		xdpValues)
}
