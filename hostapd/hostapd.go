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

// Package hostapd implements communicating with hostapd over its control socket.
package hostapd

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
)

type Connection struct {
	t *Transport

	cb func(Event)
}

type Event interface {
	Type() string
}

type STAConnected struct {
	MAC net.HardwareAddr
}

func (STAConnected) Type() string { return "AP-STA-CONNECTED" }

func New(ctx context.Context, raddr string) (*Connection, error) {
	t, err := Dial(raddr)
	if err != nil {
		return nil, err
	}

	return FromTransport(ctx, t)
}

func FromTransport(ctx context.Context, t *Transport) (*Connection, error) {
	c := &Connection{
		t: t,
	}
	t.RegisterCallback(ctx, c.eventHandler)
	return c, nil
}

func (c *Connection) eventHandler(s string) {
	if c.cb == nil {
		// do nothing
	}

	// trim off the beginning
	if s[0] == '<' {
		s = s[strings.Index(s, ">")+1:]
	}

	if s == "" {
		log.Printf("hostapd: hostapd sent us nothing? (in eventHandler)")
		return
	}

	bits := strings.SplitN(s, " ", 2)
	switch bits[0] {
	case "AP-STA-CONNECTED":
		mac, err := net.ParseMAC(bits[1])
		if err != nil {
			log.Printf("hostapd: failed to parse MAC in %q: %v", s, err)
		}
		c.cb(STAConnected{mac})
	default:
		log.Printf("hostapd: unhandled message %q", s)
		// too lazy to figure the rest out, whatever
	}
}

func (c *Connection) RegisterCallback(cb func(Event)) {
	c.cb = cb
}

func (c *Connection) ListStations(ctx context.Context) (map[string]map[string]string, error) {
	msg := "STA-FIRST"
	ret := make(map[string]map[string]string)

	for {
		resp, err := c.t.Transceive(ctx, msg)
		if err != nil {
			return nil, err
		}

		if resp == "" {
			break
		}

		m := make(map[string]string)
		pieces := strings.Split(resp, "\n")
		for _, ln := range pieces[1:] {
			if ln == "" {
				break
			}
			bits := strings.SplitN(ln, "=", 2)
			m[bits[0]] = bits[1]
		}
		ret[pieces[0]] = m
		msg = fmt.Sprintf("STA-NEXT %s", pieces[0])
	}
	return ret, nil
}