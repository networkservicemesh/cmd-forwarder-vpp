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

// Package devicecfg provides service domain to device config
package devicecfg

import (
	"context"
	"fmt"
	"strings"

	"github.com/pkg/errors"

	"github.com/networkservicemesh/sdk-sriov/pkg/tools/yamlhelper"
	"github.com/networkservicemesh/sdk/pkg/tools/log/logruslogger"
)

const linuxIfMaxLength int = 15

// Config contains list of available service domains
type Config struct {
	Interfaces []*Device `yaml:"interfaces"`
}

func (c *Config) String() string {
	sb := &strings.Builder{}
	_, _ = sb.WriteString("&{")

	_, _ = sb.WriteString("Interfaces:[")
	var strs []string
	for _, device := range c.Interfaces {
		strs = append(strs, fmt.Sprintf("%+v", device))
	}

	_, _ = sb.WriteString(strings.Join(strs, " "))
	_, _ = sb.WriteString("]")

	_, _ = sb.WriteString("}")
	return sb.String()
}

// Device contains an available interface name and related matches
type Device struct {
	Name    string       `yaml:"name"`
	Matches []*Selectors `yaml:"matches"`
}

func (iface *Device) String() string {
	sb := &strings.Builder{}
	_, _ = sb.WriteString("&{")

	_, _ = sb.WriteString("Name:")
	_, _ = sb.WriteString(iface.Name)

	_, _ = sb.WriteString(" Matches:[")
	var strs []string
	for _, selector := range iface.Matches {
		strs = append(strs, fmt.Sprintf("%+v", selector))
	}

	_, _ = sb.WriteString(strings.Join(strs, " "))
	_, _ = sb.WriteString("]")

	_, _ = sb.WriteString("}")
	return sb.String()
}

// Selectors contains a list of selectors
type Selectors struct {
	LabelSelector []*Labels `yaml:"labelSelector"`
}

func (mh *Selectors) String() string {
	sb := &strings.Builder{}
	_, _ = sb.WriteString("&{")

	_, _ = sb.WriteString("LabelSelector[")
	var strs []string
	for _, labelSel := range mh.LabelSelector {
		strs = append(strs, fmt.Sprintf("%+v", labelSel))
	}
	_, _ = sb.WriteString(strings.Join(strs, " "))
	_, _ = sb.WriteString("]")

	_, _ = sb.WriteString("}")
	return sb.String()
}

// Labels contins the via selector
type Labels struct {
	Via string `yaml:"via"`
}

// ReadConfig reads configuration from file
func ReadConfig(ctx context.Context, configFile string) (*Config, error) {
	logger := logruslogger.New(ctx)

	cfg := &Config{}
	if err := yamlhelper.UnmarshalFile(configFile, cfg); err != nil {
		return nil, err
	}

	for _, device := range cfg.Interfaces {
		if device.Name == "" {
			return nil, errors.Errorf("intrface name must be set")
		}
		if len(device.Name) >= linuxIfMaxLength {
			return nil, errors.Errorf("too long interface name set")
		}
		for i := range device.Matches {
			if len(device.Matches[i].LabelSelector) == 0 {
				return nil, errors.Errorf("at least one label selector must be specified")
			}
			for j := range device.Matches[i].LabelSelector {
				if device.Matches[i].LabelSelector[j].Via == "" {
					return nil, errors.Errorf("%s unsupported label selector specified", device.Name)
				}
			}
		}
	}

	logger.WithField("Config", "ReadConfig").Infof("unmarshalled Config: %+v", cfg)

	return cfg, nil
}
