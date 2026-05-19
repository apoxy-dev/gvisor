// Copyright 2018 The gVisor Authors.
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

// Package filter installs seccomp filters to prevent prohibited syscalls
// in case it's compromised.
package filter

import (
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/runsc/boot/filter/config"
)

// ***   DEBUG TIP   ***
// If you suspect the Sentry is getting killed due to a seccomp violation,
// change this to `true` to get a panic stack trace when there is a
// violation.
const debugFilter = false

// apoxyDefaultAction overrides upstream's default seccomp action (which
// is RET_KILL_PROCESS via saneDefaultAction). ENOSYS matches the kernel's
// own behavior for unknown syscalls, so well-written probing code (Go
// runtime fallback paths, version-detect probes) handles it gracefully.
// Empirically the upstream KILL_PROCESS default killed the Sentry on a
// rare (~10–20%) intermittent unknown-syscall path during sandbox
// bring-up; ENOSYS lets the same call return cleanly and the Sentry
// proceeds. The allow-list (the actual security boundary) is unchanged.
//
// Note: precompiled BPF programs are generated upstream with the
// KILL_PROCESS default baked in, so this override implies bypassing the
// precompiled fast path; Install() does so unconditionally below.
const apoxyDefaultAction = seccomp.Action("return_error:26") // 38 = ENOSYS

// Options is a re-export of the config Options type under this package.
type Options = config.Options

// Install seccomp filters based on the given platform.
func Install(opt Options) error {
	for _, warning := range config.Warnings(opt) {
		log.Warningf("*** SECCOMP WARNING: %s", warning)
	}
	// Always build from scratch (skip precompiled): the precompiled
	// programs are generated with upstream's KILL_PROCESS default, which
	// conflicts with apoxyDefaultAction.
	key := opt.ConfigKey()
	seccompOpts := config.SeccompOptions(opt)
	seccompOpts.DefaultAction = apoxyDefaultAction
	if debugFilter {
		log.Infof("Seccomp filter debugging is enabled; seccomp failures will result in a panic stack trace.")
		seccompOpts.DefaultAction = seccomp.Trap
	} else {
		log.Infof("Building seccomp program from scratch (apoxy fork: ENOSYS default) for config options %v.", key)
	}
	rules, denyRules := config.Rules(opt)
	program := &seccomp.Program{
		RuleSets: []seccomp.RuleSet{
			{
				Rules: denyRules,
			},
			{
				Rules:  rules,
				Action: seccomp.Allow,
			},
		},
		Options: seccompOpts,
	}
	return program.Install()
}
