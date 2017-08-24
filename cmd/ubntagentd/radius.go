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

package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"

	pb "github.com/lukegb/captivate/captivated"
	"github.com/lukegb/captivate/ubiquiti"
	"golang.org/x/net/context"
)

const (
	radiusBufSize = 65535
)

type radiusHandler struct {
	c pb.CaptivateClient
}

func (h *radiusHandler) ServeRADIUS(w radius.ResponseWriter, r *radius.Request) {
	ctx := r.Context()

	pkt := r.Packet
	if pkt.Code != radius.CodeAccessRequest {
		log.Printf("radius[%v]: unexpected packet code %v", r.RemoteAddr, pkt.Code)
		return
	}

	err := func() error {
		username, err := rfc2865.UserName_LookupString(pkt)
		if err != nil {
			return fmt.Errorf("username: %v", err)
		}

		password, err := rfc2865.UserPassword_LookupString(pkt)
		if err != nil {
			return fmt.Errorf("password: %v", err)
		}

		if username != password {
			return fmt.Errorf("username (%v) doesn't match password (%v)", username, password)
		}

		// mangle username into something we might be able to parse
		if len(username) != 12 {
			return fmt.Errorf("username (%v) isn't MAC-long", username)
		}
		macStr := fmt.Sprintf("%s:%s:%s:%s:%s:%s", username[0:2], username[2:4], username[4:6], username[6:8], username[8:10], username[10:12])

		mac, err := net.ParseMAC(macStr)
		if err != nil {
			return fmt.Errorf("can't parse username as MAC: %v", err)
		}

		resp, err := h.c.SawClient(ctx, &pb.SawClientRequest{
			Mac: mac.String(),
		})
		if err != nil {
			return fmt.Errorf("captivated returned error: %v", err)
		}

		log.Printf("radius: assigning %s to VLAN %d", mac, resp.Vlan)
		if err := ubiquiti.SetVLAN(mac, resp.Vlan); err != nil {
			return fmt.Errorf("error assigning to VLAN: %s", err)
		}

		go func() {
			// spray and pray
			for n := 0; n < 100; n++ {
				log.Printf("radius: assigning %s to VLAN %d - %d", mac, resp.Vlan, n)
				if err := ubiquiti.SetVLAN(mac, resp.Vlan); err != nil {
					return
				}
				time.Sleep(50 * time.Millisecond)
			}
		}()

		return nil
	}()
	if err != nil {
		log.Printf("radius[%v]: %v", r.RemoteAddr, err)
		w.Write(r.Response(radius.CodeAccessReject))
		return
	}
	w.Write(r.Response(radius.CodeAccessAccept))
}

type radiusContextWrapper struct {
	wrapped radius.Handler
	timeout time.Duration
}

func (h radiusContextWrapper) ServeRADIUS(w radius.ResponseWriter, r *radius.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	h.wrapped.ServeRADIUS(w, r.WithContext(ctx))
	cancel()
}

type radiusOptions struct {
	Captivate pb.CaptivateClient
	Secret    []byte
}

func radiusServer(rctx context.Context, pconn net.PacketConn, o radiusOptions) {
	go func() {
		<-rctx.Done()
		pconn.Close()
	}()

	h := &radiusHandler{
		c: o.Captivate,
	}
	s := &radius.PacketServer{
		Handler:      radiusContextWrapper{h, 1 * time.Second},
		SecretSource: radius.StaticSecretSource(o.Secret),
	}
	if err := s.Serve(pconn); err != nil {
		log.Printf("radius: Serve: %v", err)
	}
}
