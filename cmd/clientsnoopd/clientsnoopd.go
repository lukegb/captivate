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
	"flag"
	"log"
	"net"
	"sync"
	"time"

	pb "github.com/lukegb/captivate/captivated"
	"google.golang.org/grpc"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	flagInterface      = flag.String("iface", "br300", "interface to watch for ICMP6/DHCP traffic")
	flagCaptivatedAddr = flag.String("captivated-addr", "[::1]:21000", "address to connect to captivated on")
)

type ratelimiter struct {
	mu       sync.RWMutex
	lastSent map[string]time.Time
}

func (r *ratelimiter) expiryRoutine() {
	t := time.NewTicker(1 * time.Minute)
	for {
		cutoff := r.cutoff()
		r.mu.Lock()
		for k, last := range r.lastSent {
			if last.Before(cutoff) {
				log.Printf("removing %v from ratelimiter", k)
				delete(r.lastSent, k)
			}
		}
		r.mu.Unlock()
		<-t.C
	}
}

func (r *ratelimiter) cutoff() time.Time {
	return time.Now().Add(-1 * time.Minute)
}

func (r *ratelimiter) ShouldSend(k string) bool {
	// Note that we do not guarantee exactly one message per time interval.
	r.mu.RLock()
	t, ok := r.lastSent[k]
	r.mu.RUnlock()
	if !ok || t.Before(r.cutoff()) {
		r.mu.Lock()
		r.lastSent[k] = time.Now()
		r.mu.Unlock()
		return true
	}
	return false
}

func newRatelimiter() *ratelimiter {
	r := &ratelimiter{
		lastSent: make(map[string]time.Time),
	}
	go r.expiryRoutine()
	return r
}

func main() {
	flag.Parse()
	ctx := context.Background()

	r := newRatelimiter()

	conn, err := grpc.Dial(*flagCaptivatedAddr, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("grpc.Dial(%v): %v", *flagCaptivatedAddr, err)
	}

	c := pb.NewCaptivateClient(conn)

	intf, err := net.InterfaceByName(*flagInterface)
	if err != nil {
		log.Fatalf("InterfaceByName(%v): %v", *flagInterface, err)
	}

	inh, err := pcap.NewInactiveHandle(intf.Name)
	if err != nil {
		log.Fatalf("pcap.NewInactiveHandle: %v", err)
	}
	defer inh.CleanUp()
	if err := inh.SetImmediateMode(true); err != nil {
		log.Fatalf("SetImmediateMode(true): %v", err)
	}
	if err := inh.SetSnapLen(65536); err != nil {
		log.Fatalf("SetSnapLen(65536): %v", err)
	}

	handle, err := inh.Activate()
	if err != nil {
		log.Fatalf("pcap.Activate: %v", err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("(udp and port 67 and ether host ff:ff:ff:ff:ff:ff) or (icmp6 and ether host 33:33:00:00:00:02)"); err != nil {
		log.Fatalf("SetBPFFilter: %v", err)
	}

	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	for {
		pkt, err := src.NextPacket()
		if err != nil {
			log.Fatalf("NextPacket: %v", err)
		}

		ethl := pkt.Layer(layers.LayerTypeEthernet)
		if ethl == nil {
			log.Printf("packet was lacking Ethernet layer?")
			continue
		}
		eth := ethl.(*layers.Ethernet)

		m := eth.SrcMAC
		if m[0] == 0xff || m[0] == 0x33 {
			m = eth.DstMAC
		}

		ms := m.String()

		if r.ShouldSend(ms) {
			log.Printf("sending SawClient for %s", ms)
			_, err := c.SawClient(ctx, &pb.SawClientRequest{Mac: ms})
			if err != nil {
				log.Printf("SawClient(%s): %v", ms, err)
			}
		}
	}
}
