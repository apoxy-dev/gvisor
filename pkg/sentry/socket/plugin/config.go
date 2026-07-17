// Copyright 2023 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package plugin

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/seccomp"
)

// SeccompFilters defines seccomp allowed rules that are needed by plugin
// network stacks.
//
// Two kinds of plugin implementations exist in the tree:
//
//   - CGO/DPDK-style plugins which call out into a userspace network library
//     that allocates shared-memory segments. These need MMAP with the
//     specific MAP_SHARED|MAP_ANONYMOUS|MAP_FIXED triple.
//   - Native-Go plugins (e.g. plugins that implement the inet.Stack interface
//     directly and dial host sockets to forward upstream). These need the
//     same outbound-networking syscalls that hostinet allows, because they
//     run net.Dial / unix.Socket from inside the Sentry process.
//
// We allow both. The native-Go ruleset mirrors hostInetFilters in
// runsc/boot/filter/config/extra_filters_hostinet.go but is duplicated here
// (rather than imported) because the plugin package must not depend on
// runsc-internal packages.
// SeccompUnixgramDGram is a coordination sentinel for downstreams that rely on
// this fork's plugin seccomp filter permitting AF_UNIX SOCK_DGRAM socket
// creation (see the SYS_SOCKET rules in SeccompFilters). It is 1 while that
// allowance is present and must be set to 0 if the AF_UNIX SOCK_DGRAM rule is
// ever removed. Downstreams (apoxy-cli's sentrystack, which dials a host
// unixgram DNS resolver from inside the Sentry) static-assert on it so a
// gvisor pin bump that drops this fork patch fails to build instead of
// silently breaking guest DNS forwarding at runtime.
const SeccompUnixgramDGram = 1

func SeccompFilters() seccomp.SyscallRules {
	rules := seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
		// DPDK alloc_seg.
		unix.SYS_MMAP: seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(
				unix.MAP_SHARED |
					unix.MAP_ANONYMOUS |
					unix.MAP_FIXED),
		},

		// Native-Go plugins: outbound dial + I/O.
		unix.SYS_BIND:        seccomp.MatchAll{},
		unix.SYS_CONNECT:     seccomp.MatchAll{},
		unix.SYS_GETPEERNAME: seccomp.MatchAll{},
		unix.SYS_GETSOCKNAME: seccomp.MatchAll{},
		unix.SYS_LISTEN:      seccomp.MatchAll{},
		unix.SYS_ACCEPT4: seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC),
		},
		unix.SYS_RECVFROM: seccomp.MatchAll{},
		unix.SYS_RECVMSG:  seccomp.MatchAll{},
		unix.SYS_SENDTO:   seccomp.MatchAll{},
		unix.SYS_SENDMSG:  seccomp.MatchAll{},
		unix.SYS_READV:    seccomp.MatchAll{},
		unix.SYS_WRITEV:   seccomp.MatchAll{},
		unix.SYS_SHUTDOWN: seccomp.Or{
			seccomp.PerArg{
				seccomp.AnyValue{},
				seccomp.EqualTo(unix.SHUT_RD),
			},
			seccomp.PerArg{
				seccomp.AnyValue{},
				seccomp.EqualTo(unix.SHUT_WR),
			},
			seccomp.PerArg{
				seccomp.AnyValue{},
				seccomp.EqualTo(unix.SHUT_RDWR),
			},
		},
		// Native-Go plugins use Go's netpoll, which (re)configures
		// non-blocking + cloexec via fcntl, sets SO_REUSEADDR, etc.
		unix.SYS_FCNTL: seccomp.Or{
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(unix.F_GETFL),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(unix.F_SETFL),
				seccomp.AnyValue{},
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(unix.F_GETFD),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(unix.F_SETFD),
				seccomp.AnyValue{},
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(unix.F_DUPFD_CLOEXEC),
				seccomp.AnyValue{},
			},
		},
	})

	// Socket creation: AF_INET / AF_INET6 with SOCK_DGRAM or SOCK_STREAM,
	// optionally OR'd with SOCK_NONBLOCK and SOCK_CLOEXEC. Used by
	// net.Dial("udp"/"tcp", ...) and raw unix.Socket().
	//
	// AF_UNIX is allowed for SOCK_DGRAM only: native-Go plugin stacks dial
	// host unixgram sockets (abstract-namespace, so reachable from the
	// chrooted Sentry) to forward guest DNS to a per-sandbox host resolver.
	// AF_UNIX SOCK_STREAM stays denied — no plugin needs it, so there is no
	// reason to widen the boundary for it. Note this does NOT by itself block
	// SCM_RIGHTS fd-passing: that rides datagram unix sockets too, and
	// SYS_SENDMSG/SYS_RECVMSG are unconstrained here. fd smuggling is instead
	// contained by there being no cooperating peer that sends fds (the only
	// intended peer is the trusted resident resolver) — a post-Sentry-compromise
	// defense-in-depth consideration, not a guest-reachable syscall gate.
	socketRules := seccomp.Or{}
	type familyTypes struct {
		family uintptr
		stypes []uintptr
	}
	for _, ft := range []familyTypes{
		{unix.AF_INET, []uintptr{unix.SOCK_DGRAM, unix.SOCK_STREAM}},
		{unix.AF_INET6, []uintptr{unix.SOCK_DGRAM, unix.SOCK_STREAM}},
		{unix.AF_UNIX, []uintptr{unix.SOCK_DGRAM}},
	} {
		for _, stype := range ft.stypes {
			for _, flags := range []uintptr{
				0,
				linux.SOCK_NONBLOCK,
				linux.SOCK_CLOEXEC,
				linux.SOCK_NONBLOCK | linux.SOCK_CLOEXEC,
			} {
				socketRules = append(socketRules, seccomp.PerArg{
					seccomp.EqualTo(ft.family),
					seccomp.EqualTo(stype | flags),
					seccomp.AnyValue{},
				})
			}
		}
	}
	rules.Set(unix.SYS_SOCKET, socketRules)

	// {Get,Set}sockopt: allow the small set Go's net package actually
	// touches when configuring outbound sockets. SOL_SOCKET options for
	// SO_BROADCAST, SO_REUSEADDR, SO_REUSEPORT, SO_KEEPALIVE,
	// SO_LINGER, SO_SNDBUF, SO_RCVBUF, SO_ERROR, SO_TYPE; plus the
	// IP/IPV6 options for IP_PKTINFO and IPV6_V6ONLY which Go probes.
	soSockOpts := []uintptr{
		unix.SO_BROADCAST, unix.SO_REUSEADDR, unix.SO_REUSEPORT,
		unix.SO_KEEPALIVE, unix.SO_LINGER, unix.SO_SNDBUF, unix.SO_RCVBUF,
		unix.SO_ERROR, unix.SO_TYPE, unix.SO_DOMAIN, unix.SO_PROTOCOL,
		unix.SO_RCVTIMEO, unix.SO_SNDTIMEO,
	}
	for _, opt := range soSockOpts {
		rules.Add(unix.SYS_GETSOCKOPT, seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.SOL_SOCKET),
			seccomp.EqualTo(opt),
		})
		rules.Add(unix.SYS_SETSOCKOPT, seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.SOL_SOCKET),
			seccomp.EqualTo(opt),
		})
	}
	for _, ipOpt := range []uintptr{unix.IP_PKTINFO, unix.IP_TOS, unix.IP_TTL, unix.IP_RECVTOS} {
		rules.Add(unix.SYS_GETSOCKOPT, seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.IPPROTO_IP),
			seccomp.EqualTo(ipOpt),
		})
		rules.Add(unix.SYS_SETSOCKOPT, seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.IPPROTO_IP),
			seccomp.EqualTo(ipOpt),
		})
	}
	for _, ip6Opt := range []uintptr{unix.IPV6_V6ONLY, unix.IPV6_RECVPKTINFO, unix.IPV6_TCLASS, unix.IPV6_UNICAST_HOPS} {
		rules.Add(unix.SYS_GETSOCKOPT, seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.IPPROTO_IPV6),
			seccomp.EqualTo(ip6Opt),
		})
		rules.Add(unix.SYS_SETSOCKOPT, seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.IPPROTO_IPV6),
			seccomp.EqualTo(ip6Opt),
		})
	}
	for _, tcpOpt := range []uintptr{unix.TCP_NODELAY, unix.TCP_KEEPIDLE, unix.TCP_KEEPINTVL, unix.TCP_KEEPCNT, unix.TCP_USER_TIMEOUT} {
		rules.Add(unix.SYS_GETSOCKOPT, seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.IPPROTO_TCP),
			seccomp.EqualTo(tcpOpt),
		})
		rules.Add(unix.SYS_SETSOCKOPT, seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.IPPROTO_TCP),
			seccomp.EqualTo(tcpOpt),
		})
	}

	return rules
}
