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

package vppinit

import (
	"context"
	"time"

	"go.fd.io/govpp/api"

	"github.com/networkservicemesh/sdk/pkg/tools/extend"
	"github.com/networkservicemesh/sdk/pkg/tools/log"
)

type safeVPPConnection struct {
	api.Connection
	contextTimeout time.Duration
}

// NewSafeVPPConnection - creates a wrapper for vpp connection that uses extended context timeout for all operations
func NewSafeVPPConnection(vppConn api.Connection, contextTimeout time.Duration) api.Connection {
	return &safeVPPConnection{
		Connection:     vppConn,
		contextTimeout: contextTimeout,
	}
}

func (c *safeVPPConnection) Invoke(ctx context.Context, req, reply api.Message) error {
	ctx, cancel := c.ToSafeContext(ctx)
	err := c.Connection.Invoke(ctx, req, reply)
	cancel()
	return err
}

func (c *safeVPPConnection) ToSafeContext(ctx context.Context) (context.Context, func()) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return ctx, func() {}
	}

	minDeadline := time.Now().Add(c.contextTimeout)
	if minDeadline.After(deadline) {
		deadline = minDeadline
		log.FromContext(ctx).Infof("Context deadline has been increased due to important request(s)")
	}
	postponedCtx, cancel := context.WithDeadline(context.Background(), deadline)
	return extend.WithValuesFromContext(postponedCtx, ctx), cancel
}
