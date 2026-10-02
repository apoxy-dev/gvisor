// Copyright 2026 The gVisor Authors.
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

package syserr

import (
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux/errno"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// TestTranslateNetstackICMPErrors checks the errno of the errors that an ICMP
// destination unreachable gives to a socket.
func TestTranslateNetstackICMPErrors(t *testing.T) {
	cases := []struct {
		err  tcpip.Error
		want errno.Errno
	}{
		{err: &tcpip.ErrPermissionDenied{}, want: errno.EACCES},
		{err: &tcpip.ErrHostUnreachable{}, want: errno.EHOSTUNREACH},
		{err: &tcpip.ErrNetworkUnreachable{}, want: errno.ENETUNREACH},
		{err: &tcpip.ErrConnectionRefused{}, want: errno.ECONNREFUSED},
	}
	for _, tc := range cases {
		t.Run(tc.err.String(), func(t *testing.T) {
			if got := TranslateNetstackError(tc.err).ToLinux(); got != tc.want {
				t.Errorf("TranslateNetstackError(%T).ToLinux() = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}
