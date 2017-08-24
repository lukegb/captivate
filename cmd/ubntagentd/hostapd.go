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
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	pb "github.com/lukegb/captivate/captivated"
	"github.com/lukegb/captivate/hostapd"
	"github.com/lukegb/captivate/ubiquiti"
)

type hostapWatcher struct {
	mu        sync.Mutex
	intfConns map[string]*hostapd.Connection

	c pb.CaptivateClient
}

func (w *hostapWatcher) pingTestLocked() {
	rctx := context.Background()
	for intf, v := range w.intfConns {
		ctx, cancel := context.WithTimeout(rctx, 1*time.Second)
		if err := v.Ping(ctx); err != nil {
			log.Printf("hostapd: Ping %q failed - removing it: %v", intf, err)
			delete(w.intfConns, intf)
		}
		cancel()
	}
}

func (w *hostapWatcher) ensureAllLocked() {
	socks, err := hostapd.ListTransports("")
	if err != nil {
		log.Printf("hostapd: ListTransports: %v", err)
		return
	}

	mismatch := make(map[string]int)
	for intf := range w.intfConns {
		mismatch[intf]--
	}
	for _, intf := range socks {
		mismatch[intf]++
	}

	for intf, v := range mismatch {
		switch v {
		case 1:
			log.Printf("hostapd: intf %q has appeared", intf)
			if err := w.connectLocked(intf); err != nil {
				log.Printf("hostapd: connect to %q: %v", intf, err)
			}
		case -1:
			log.Printf("hostapd: intf %q has disappeared", intf)
			if err := w.disconnectLocked(intf); err != nil {
				log.Printf("hostapd: disconnect from %q: %v", intf, err)
			}
		}
	}
}

func (w *hostapWatcher) connectLocked(intf string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := hostapd.New(ctx, intf)
	if err != nil {
		return err
	}

	stas, err := conn.ListStations(ctx)
	if err != nil {
		return err
	}

	for staStr := range stas {
		sta, err := net.ParseMAC(staStr)
		if err != nil {
			return fmt.Errorf("hostapd: got garbage MAC %q from %v: %v", staStr, intf, err)
		}

		resp, err := w.c.SawClient(ctx, &pb.SawClientRequest{
			Mac: sta.String(),
		})
		if err != nil {
			return fmt.Errorf("captivated returned error for %v: %v", sta, err)
		}

		log.Printf("hostapd[%v]: assigning %v to VLAN %d", intf, sta, resp.Vlan)
		if err := ubiquiti.SetVLANOnInterface(intf, sta, resp.Vlan); err != nil {
			return fmt.Errorf("ubiquiti returned error for assigning %v to VLAN %d on %v: %v", sta, resp.Vlan, intf, err)
		}
	}

	w.intfConns[intf] = conn
	return nil
}

func (w *hostapWatcher) disconnectLocked(intf string) error {
	err := w.intfConns[intf].Close()
	delete(w.intfConns, intf)
	return err
}

func (w *hostapWatcher) run() {
	t := time.NewTicker(10 * time.Second)
	for {
		w.mu.Lock()

		w.pingTestLocked()
		w.ensureAllLocked()
		w.pingTestLocked()

		w.mu.Unlock()

		<-t.C
	}
}

func macEqual(a, b net.HardwareAddr) bool {
	if len(a) != len(b) {
		return false
	}
	for n := range a {
		if a[n] != b[n] {
			return false
		}
	}
	return true
}

func (w *hostapWatcher) VLANChanged(mac net.HardwareAddr) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for intf, c := range w.intfConns {
		stas, err := c.ListStations(ctx)
		if err != nil {
			log.Printf("hostapd: VLANChanged ListStations on %v: %v", intf, err)
			continue
		}

		for staStr := range stas {
			sta, err := net.ParseMAC(staStr)
			if err != nil {
				log.Printf("hostapd: got garbage MAC %q from %v: %v", staStr, intf, err)
				continue
			}
			if macEqual(sta, mac) {
				if err := c.Disassociate(ctx, mac); err != nil {
					log.Printf("hostapd: Disassociate %v on %v: %v", mac, intf, err)
				}
				break
			}
		}
	}

	return nil
}

func hostap(c pb.CaptivateClient) *hostapWatcher {
	w := &hostapWatcher{
		intfConns: make(map[string]*hostapd.Connection),
		c:         c,
	}
	go w.run()
	return w
}
