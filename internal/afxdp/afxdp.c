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

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

#define ntohs(x)        __constant_ntohs(x)
#define MAX_NR_PORTS    65535

// nsm_xdp_pinhole contains NSM UDP ports. It is filled by afxdppinhole chain element
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_NR_PORTS);
    __type(key, unsigned short int);
    __type(value, unsigned short int);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} nsm_xdp_pinhole SEC(".maps");

// xsks_map redirects raw XDP frames to AF_XDP sockets (XSKs). It is filled by VPP plugin
// https://docs.kernel.org/bpf/map_xskmap.html
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, int);
    __type(value, int);
} xsks_map SEC(".maps");

SEC("xdp_sock")
int xdp_sock_prog(struct xdp_md *ctx) {
    const void *data = (void *)(long)ctx->data;
    const void *data_end = (void *)(long)ctx->data_end;

    if (data + sizeof(struct ethhdr) > data_end) {
        // the packet is too small
        return XDP_PASS;
    }

    const struct ethhdr *eth = data;
    // Here we check if a packet belongs to NSM. We do this with a UDP port map, which is filled on NSM request.
    // It's a kind of pinhole
    if (eth->h_proto == ntohs(ETH_P_IP)) {
        // IPv4 case
        // Check the packet size
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end) {
            return XDP_PASS;
        }
        const struct iphdr *ip = (void *)(eth + 1);
        if (ip->protocol == IPPROTO_UDP) {
            const struct udphdr *udp = (void *)(ip + 1);
            const unsigned int port = ntohs(udp->dest);
            if (bpf_map_lookup_elem(&nsm_xdp_pinhole, &port)) {
                return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
            }
        }
    } else if (eth->h_proto == ntohs(ETH_P_IPV6)) {
        // IPv6 case
        // Check the packet size
        if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct udphdr) > data_end) {
            return XDP_PASS;
        }
        const struct ipv6hdr *ip = (void *)(eth + 1);
        if (ip->nexthdr == IPPROTO_UDP) {
            const struct udphdr *udp = (void *)(ip + 1);
            const unsigned int port = ntohs(udp->dest);
            if (bpf_map_lookup_elem(&nsm_xdp_pinhole, &port)) {
                return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
            }
        }
    }
    return XDP_PASS;
}

