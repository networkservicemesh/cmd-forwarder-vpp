// Copyright (c) 2021 Nordix Foundation.
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

package devicecfg_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/networkservicemesh/cmd-forwarder-vpp/internal/devicecfg"
)

const (
	configFileName = "config.yml"
	ifName1        = "eth1"
	ifName2        = "eth2"
	ifName3        = "eth3"
	ifName4        = "eth4"
	via1           = "gw0"
	via2           = "gw1"
	via3           = "gw2"
	via4           = "gw3"
)

func TestReadConfigFile(t *testing.T) {
	cfg, err := devicecfg.ReadConfig(context.Background(), configFileName)
	require.NoError(t, err)
	require.Equal(t, &devicecfg.Config{
		Interfaces: []*devicecfg.Device{
			{
				Name: ifName1,
				Matches: []*devicecfg.Selectors{
					{
						LabelSelector: []*devicecfg.Labels{
							{
								Via: via1,
							},
						},
					},
				},
			},
			{
				Name: ifName2,
				Matches: []*devicecfg.Selectors{
					{
						LabelSelector: []*devicecfg.Labels{
							{
								Via: via2,
							},
						},
					},
					{
						LabelSelector: []*devicecfg.Labels{
							{
								Via: via3,
							},
						},
					},
				},
			},
			{
				Name: ifName3,
				Matches: []*devicecfg.Selectors{
					{
						LabelSelector: []*devicecfg.Labels{
							{
								Via: via3,
							},
						},
					},
				},
			},
			{
				Name: ifName4,
				Matches: []*devicecfg.Selectors{
					{
						LabelSelector: []*devicecfg.Labels{
							{
								Via: via3,
							},
						},
					},
					{
						LabelSelector: []*devicecfg.Labels{
							{
								Via: via4,
							},
						},
					},
				},
			},
		},
	}, cfg)
}
