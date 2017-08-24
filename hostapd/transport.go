/*
Copyright 2017 Luke Granger-Brown

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package hostapd

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

var (
	counterMu sync.Mutex
	counter   int
)

// CallbackFunc is the prototype used for registering callbacks for unsolicited messages.
type CallbackFunc func(msg string)

// Transport represents a raw connection to hostapd or wpa_supplicant.
type Transport struct {
	sock *net.UnixConn
	cb   CallbackFunc

	readMu sync.Mutex
	readCh chan<- string

	close chan struct{}
}

func (s *Transport) recver() {
	buf := make([]byte, 65535)
	for {
		n, _, err := s.sock.ReadFromUnix(buf)
		if err != nil {
			log.Printf("hostapd: ReadFromUnix got error: %v", err)
			break
		}

		msg := string(buf[:n])
		if len(msg) >= 1 && msg[0] == '<' {
			// unsolicited message
			if s.cb != nil {
				go s.cb(msg)
			}
		} else {
			// response to request
			if s.readCh == nil {
				// ???
				log.Printf("hostapd sent us a message (%v) but noone is waiting for it", msg)
			} else {
				select {
				case <-s.close:
					return
				case s.readCh <- msg:
				}
			}
		}
	}
}

// RegisterCallback registers a callback function for unsolicited messages from hostapd (e.g. event notifications).
// Passing nil will deregister any existing callback. Only one callback can be registered at a time.
func (s *Transport) RegisterCallback(ctx context.Context, cb func(msg string)) error {
	var cmd string
	switch {
	case s.cb == nil && cb != nil:
		cmd = "ATTACH"
	case s.cb != nil && cb == nil:
		cmd = "DETACH"
	}
	if cmd != "" {
		resp, err := s.Transceive(ctx, cmd)
		if err != nil {
			return err
		}
		if resp != "OK\n" {
			return fmt.Errorf("hostapd returned %v; want OK", resp)
		}
	}

	s.cb = cb
	return nil
}

// Transceive transmits a raw hostapd message, and returns the response.
func (s *Transport) Transceive(ctx context.Context, req string) (string, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	readCh := make(chan string)
	s.readCh = readCh
	defer func() { s.readCh = nil }()

	if _, err := fmt.Fprintf(s.sock, "%s", req); err != nil {
		return "", err
	}

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-s.close:
		return "", fmt.Errorf("shutting down on request")
	case resp := <-readCh:
		return resp, nil
	}
}

// Close closes the UNIX socket connected to hostapd.
func (s *Transport) Close() error {
	close(s.close)
	return s.sock.Close()
}

// Dial opens a new connection to hostapd on the given socket.
func Dial(raddr string) (*Transport, error) {
	return Dial2(raddr, "")
}

func isAddrInUse(err error) bool {
	if err, ok := err.(*net.OpError); ok {
		if err, ok := err.Err.(*os.SyscallError); ok {
			if err, ok := err.Err.(syscall.Errno); ok && err == syscall.EADDRINUSE {
				return true
			}
		}
	}
	return false
}

func dial(laddr, raddr *net.UnixAddr) (*net.UnixConn, error) {
	conn, err := net.DialUnix("unixgram", laddr, raddr)
	if err != nil {
		if isAddrInUse(err) {
			// probably a left-over socket
			oerr := err
			if err := os.Remove(laddr.String()); err != nil {
				return nil, oerr
			}
			// retry
			return dial(laddr, raddr)
		}
		return nil, err
	}
	return conn, nil
}

// Dial2 opens a new connection to hostapd at raddr, using laddr as the client end.
func Dial2(raddr, laddr string) (*Transport, error) {
	if laddr == "" {
		counterMu.Lock()
		n := counter
		counter = counter + 1
		counterMu.Unlock()

		laddr = filepath.Join(os.TempDir(), fmt.Sprintf("hostapd-client-%d-%d", os.Getpid(), n))
	}

	if !strings.Contains(raddr, "/") {
		raddr = filepath.Join(HostapdSocketDirectory, raddr)
	}

	r, err := net.ResolveUnixAddr("unixgram", raddr)
	if err != nil {
		return nil, err
	}

	l, err := net.ResolveUnixAddr("unixgram", laddr)
	if err != nil {
		return nil, err
	}

	conn, err := dial(l, r)
	if err != nil {
		return nil, err
	}

	s := &Transport{
		sock:  conn,
		close: make(chan struct{}),
	}
	go s.recver()
	return s, nil
}
