// Copyright (c) 2023 Cisco and/or its affiliates.
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

//go:build arm || arm64

package vppinit

import (
	"github.com/edwarnicke/vpphelper"
)

const (
	vppConfContents = `unix {
  nodaemon
  log %[1]s/var/log/vpp/vpp.log
  full-coredump
  cli-listen %[1]s/var/run/vpp/cli.sock
  gid vpp
}

buffers {
	# buffers-per-numa was chosen as 256 buffers/interface * 128 possible interfaces
	buffers-per-numa 32768
	# data-size was chosen using 4096 page - 256 bytes metadata - one cache line (64 bytes) - additional ARM costs (64 bytes) to just *barely* fit in
	# one page, since we can't split a buffer across a page.
	default data-size 3712
}

## logging {
##   default-syslog-log-level debug
## }

api-trace {
## This stanza controls binary API tracing. Unless there is a very strong reason,
## please leave this feature enabled.
  on
## Additional parameters:
##
## To set the number of binary API trace records in the circular buffer, configure nitems
##
## nitems <nnn>
##
## To save the api message table decode tables, configure a filename. Results in /tmp/<filename>
## Very handy for understanding api message changes between versions, identifying missing
## plugins, and so forth.
##
## save-api-table <filename>
}

api-segment {
  gid vpp
}

socksvr {
  socket-name %[1]s/var/run/vpp/api.sock
}

statseg {
  socket-name %[1]s/var/run/vpp/stats.sock
}

cpu {
	## In the VPP there is one main thread and optionally the user can create worker(s)
	## The main thread and worker thread(s) can be pinned to CPU core(s) manually or automatically

	## Manual pinning of thread(s) to CPU core(s)

	## Set logical CPU core where main thread runs, if main core is not set
	## VPP will use core 1 if available
	# main-core 1

	## Set logical CPU core(s) where worker threads are running
	# corelist-workers 2-3,18-19

	## Automatic pinning of thread(s) to CPU core(s)

	## Sets number of CPU core(s) to be skipped (1 ... N-1)
	## Skipped CPU core(s) are not used for pinning main thread and working thread(s).
	## The main thread is automatically pinned to the first available CPU core and worker(s)
	## are pinned to next free CPU core(s) after core assigned to main thread
	# skip-cores 4

	## Specify a number of workers to be created
	## Workers are pinned to N consecutive CPU cores while skipping "skip-cores" CPU core(s)
	## and main thread's CPU core
	# workers 2

	## Set scheduling policy and priority of main and worker threads

	## Scheduling policy options are: other (SCHED_OTHER), batch (SCHED_BATCH)
	## idle (SCHED_IDLE), fifo (SCHED_FIFO), rr (SCHED_RR)
	# scheduler-policy fifo

	## Scheduling priority is used only for "real-time policies (fifo and rr),
	## and has to be in the range of priorities supported for a particular policy
	# scheduler-priority 50
}

# dpdk {
	## Change default settings for all intefaces
	# dev default {
		## Number of receive queues, enables RSS
		## Default is 1
		# num-rx-queues 3

		## Number of transmit queues, Default is equal
		## to number of worker threads or 1 if no workers treads
		# num-tx-queues 3

		## Number of descriptors in transmit and receive rings
		## increasing or reducing number can impact performance
		## Default is 1024 for both rx and tx
		# num-rx-desc 512
		# num-tx-desc 512

		## VLAN strip offload mode for interface
		## Default is off
		# vlan-strip-offload on
	# }

	## Whitelist specific interface by specifying PCI address
	# dev 0000:02:00.0

	## Whitelist specific interface by specifying PCI address and in
	## addition specify custom parameters for this interface
	# dev 0000:02:00.1 {
	#	num-rx-queues 2
	# }

	## Specify bonded interface and its slaves via PCI addresses
	##
	## Bonded interface in XOR load balance mode (mode 2) with L3 and L4 headers
	# vdev eth_bond0,mode=2,slave=0000:02:00.0,slave=0000:03:00.0,xmit_policy=l34
	# vdev eth_bond1,mode=2,slave=0000:02:00.1,slave=0000:03:00.1,xmit_policy=l34
	##
	## Bonded interface in Active-Back up mode (mode 1)
	# vdev eth_bond0,mode=1,slave=0000:02:00.0,slave=0000:03:00.0
	# vdev eth_bond1,mode=1,slave=0000:02:00.1,slave=0000:03:00.1

	## Change UIO driver used by VPP, Options are: igb_uio, vfio-pci,
	## uio_pci_generic or auto (default)
	# uio-driver vfio-pci

	## Disable mutli-segment buffers, improves performance but
	## disables Jumbo MTU support
	# no-multi-seg

	## Increase number of buffers allocated, needed only in scenarios with
	## large number of interfaces and worker threads. Value is per CPU socket.
	## Default is 16384
	# num-mbufs 128000

	## Change hugepages allocation per-socket, needed only if there is need for
	## larger number of mbufs. Default is 256M on each detected CPU socket
	# socket-mem 2048,2048

	## Disables UDP / TCP TX checksum offload. Typically needed for use
	## faster vector PMDs (together with no-multi-seg)
	# no-tx-checksum-offload
# }


# plugins {
	## Adjusting the plugin path depending on where the VPP plugins are
	#	path /home/bms/vpp/build-root/install-vpp-native/vpp/lib64/vpp_plugins

	## Disable all plugins by default and then selectively enable specific plugins
	# plugin default { disable }
	# plugin dpdk_plugin.so { enable }
	# plugin acl_plugin.so { enable }

	## Enable all plugins by default and then selectively disable specific plugins
	# plugin dpdk_plugin.so { disable }
	# plugin acl_plugin.so { disable }
# }

	## Alternate syntax to choose plugin path
	# plugin_path /home/bms/vpp/build-root/install-vpp-native/vpp/lib64/vpp_plugins

# NSM specific changes below this line
plugins {
	plugin dpdk_plugin.so { disable }
}
`
)

// GetVppHelperOptions returns vpphelper options specified for GOARCH
func GetVppHelperOptions() []vpphelper.Option {
	return []vpphelper.Option{vpphelper.WithVppConfig(vppConfContents)}
}
