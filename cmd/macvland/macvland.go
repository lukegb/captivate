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
	"net"
	"sort"
	"sync"
	"syscall"

	"golang.org/x/net/context"

	pb "github.com/lukegb/captivate/captivated"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/vishvananda/netlink"

	"flag"
	"log"
	"strings"
)

var (
	flagInterfaces = flag.String("interfaces", "", "comma-separated list of valid interfaces")
	flagAddr       = flag.String("addr", "[::1]:21001", "address to listen for gRPC requests on")
)

type macDB struct {
	Interfaces []string

	mu        sync.RWMutex
	intfs     map[string]netlink.Link
	knownMACs map[string]string

	done chan struct{}
}

func (d *macDB) Run() error {
	if d.done != nil {
		return nil
	}

	ch := make(chan netlink.LinkUpdate, 10)
	d.done = make(chan struct{})
	d.intfs = make(map[string]netlink.Link)
	log.Printf("subscribing")
	if err := netlink.LinkSubscribe(ch, d.done); err != nil {
		return err
	}

	log.Printf("populating")
	if err := d.populate(); err != nil {
		return fmt.Errorf("populating DB initially: %v", err)
	}

	go d.watch(ch)
	return nil
}

func (d *macDB) watch(ch <-chan netlink.LinkUpdate) {
	log.Printf("running watcher")
	done := d.done
	for {
		select {
		case lu := <-ch:
			log.Printf("%#v (%T)", lu, lu.Link)
			ln := lu.Link
			if _, ok := ln.(*netlink.Macvlan); !ok {
				// skip things which aren't macvlan
				continue
			}
			name := ln.Attrs().Name

			if d.Interfaces != nil {
				d.mu.RLock()
				_, ok := d.intfs[name]
				d.mu.RUnlock()
				if !ok {
					// skip interfaces we don't care about
					continue
				}
			}

			d.mu.Lock()
			// if the interface is going away, then we should delete it from d.intfs instead
			if lu.Header.Type != syscall.RTM_DELLINK {
				d.intfs[name] = ln
			} else {
				delete(d.intfs, name)
			}
			if err := d.updateMACDBForInterfaceLocked(ln); err != nil {
				log.Printf("updateMACDBForInterfaceLocked(%v): %v", name, err)
			}
			d.mu.Unlock()
		case <-done:
			return
		}
	}
}

func (d *macDB) populate() error {
	d.mu.Lock()
	if d.Interfaces != nil {
		for _, intf := range d.Interfaces {
			ln, err := netlink.LinkByName(intf)
			if err != nil {
				return fmt.Errorf("LinkByName(%v): %v", intf, err)
			}
			d.intfs[ln.Attrs().Name] = ln
		}
	} else {
		// populate with all macvlan interfaces
		lns, err := netlink.LinkList()
		if err != nil {
			return fmt.Errorf("LinkList(): %v", err)
		}

		for _, ln := range lns {
			if _, ok := ln.(*netlink.Macvlan); ok {
				d.intfs[ln.Attrs().Name] = ln
			}
		}
	}
	if err := d.updateMACDBLocked(); err != nil {
		return err
	}
	d.mu.Unlock()
	return nil
}

func (d *macDB) updateMACDBLocked() error {
	newDB := make(map[string]string)
	for name, link := range d.intfs {
		mv, ok := link.(*netlink.Macvlan)
		if !ok {
			return fmt.Errorf("interface %v is not a macvlan", name)
		}

		for _, m := range mv.MACAddrs {
			ms := m.String()
			if other, ok := newDB[ms]; ok {
				log.Printf("warning: %v is associated with multiple macvlans: %v and %v; overwriting", ms, other, name)
			}
			newDB[m.String()] = name
		}
	}
	d.knownMACs = newDB
	return nil
}

func (d *macDB) updateMACDBForInterfaceLocked(ln netlink.Link) error {
	name := ln.Attrs().Name

	mv, ok := ln.(*netlink.Macvlan)
	if !ok {
		return fmt.Errorf("interface %v is not a macvlan", name)
	}

	myMACs := make(map[string]int)
	for _, m := range mv.MACAddrs {
		myMACs[m.String()] = 1
	}
	log.Printf("new macs: %v", myMACs)

	for ms, mname := range d.knownMACs {
		if name == mname && myMACs[ms] != 1 {
			delete(d.knownMACs, ms)
		}
	}

	for ms := range myMACs {
		if other, ok := d.knownMACs[ms]; ok && other != name {
			log.Printf("warning while associating with %v: %v is already associated with another macvlan: %v; overwriting", name, ms, other)
		}
		d.knownMACs[ms] = name
	}

	return nil
}

func (d *macDB) Stop() {
	log.Printf("stopping")
	if d.done != nil {
		close(d.done)
		d.done = nil
	}
}

func (d *macDB) ListInterfaces() ([]string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	intfs := make([]string, 0, len(d.intfs))
	for intf := range d.intfs {
		intfs = append(intfs, intf)
	}
	sort.Strings(intfs)

	return intfs, nil
}

func (d *macDB) GetInterfaceMACs(intf string) ([]net.HardwareAddr, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	ln, ok := d.intfs[intf]
	if !ok {
		return nil, fmt.Errorf("no such interface registered %v", intf)
	}

	mv, ok := ln.(*netlink.Macvlan)
	if !ok {
		return nil, fmt.Errorf("%v is not a macvlan", intf)
	}

	return mv.MACAddrs[:], nil
}

func (d *macDB) GetKnownMACs() ([]net.HardwareAddr, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	macs := make([]net.HardwareAddr, 0, len(d.knownMACs))
	for m := range d.knownMACs {
		mac, err := net.ParseMAC(m)
		if err != nil {
			return nil, err
		}

		macs = append(macs, mac)
	}

	return macs, nil
}

func (d *macDB) updateInterfaceLocked(oldln netlink.Link) error {
	ln, err := netlink.LinkByIndex(oldln.Attrs().Index)
	if err != nil {
		return fmt.Errorf("LinkByIndex(%v) - for %v: %v", oldln.Attrs().Index, oldln.Attrs().Name, err)
	}
	delete(d.intfs, oldln.Attrs().Name)
	d.intfs[ln.Attrs().Name] = ln

	if err := d.updateMACDBForInterfaceLocked(ln); err != nil {
		return fmt.Errorf("updateMACDBForInterfaceLocked: %v", err)
	}
	return nil
}

func (d *macDB) SetInterfaceForMAC(mac net.HardwareAddr, intf string) error {
	ms := mac.String()
	log.Printf("setting interface for %q to %q", ms, intf)
	d.mu.Lock()
	defer d.mu.Unlock()

	oldintf, ok := d.knownMACs[ms]
	if ok {
		oldln, ok := d.intfs[oldintf]
		if !ok {
			return fmt.Errorf("old interface %v not registered", oldintf)
		}
		if err := netlink.MacvlanMACAddrDel(oldln, mac); err != nil {
			return fmt.Errorf("deregistering from %v: %v", oldintf, err)
		}
		if err := d.updateInterfaceLocked(oldln); err != nil {
			return fmt.Errorf("updateInterfaceLocked(%v): %v", oldln.Attrs().Name, err)
		}
	}

	if intf == "" {
		// we're not adding it anywhere else
		return nil
	}

	ln, ok := d.intfs[intf]
	if !ok {
		return fmt.Errorf("new interface %v not registered", oldintf)
	}
	if err := netlink.MacvlanMACAddrAdd(ln, mac); err != nil {
		return fmt.Errorf("registering with %v: %v", intf, err)
	}
	if err := d.updateInterfaceLocked(ln); err != nil {
		return fmt.Errorf("updateInterfaceLocked(%v): %v", ln.Attrs().Name, err)
	}
	return nil
}

type server struct {
	d *macDB
}

func (s *server) ListInterfaces(ctx context.Context, r *pb.ListInterfacesRequest) (*pb.ListInterfacesReply, error) {
	intfs, err := s.d.ListInterfaces()
	if err != nil {
		return nil, err
	}

	resp := &pb.ListInterfacesReply{}
	for _, intf := range intfs {
		resp.Interfaces = append(resp.Interfaces, &pb.ListInterfacesReply_Interface{
			Interface: intf,
		})
	}
	return resp, nil
}

func (s *server) ListMACs(ctx context.Context, r *pb.ListMACsRequest) (*pb.ListMACsReply, error) {
	macs, err := s.d.GetKnownMACs()
	if err != nil {
		return nil, err
	}

	resp := &pb.ListMACsReply{}
	for _, mac := range macs {
		resp.Macs = append(resp.Macs, &pb.ListMACsReply_MAC{
			Mac: mac.String(),
		})
	}
	return resp, nil
}

func (s *server) GetInterface(ctx context.Context, r *pb.GetInterfaceRequest) (*pb.GetInterfaceReply, error) {
	macs, err := s.d.GetInterfaceMACs(r.Interface)
	if err != nil {
		return nil, err
	}

	macStrs := make([]string, len(macs))
	for n, mac := range macs {
		macStrs[n] = mac.String()
	}

	return &pb.GetInterfaceReply{
		Interface:     r.Interface,
		AuthorisedMac: macStrs,
	}, nil
}

func (s *server) Authorise(ctx context.Context, r *pb.AuthoriseRequest) (*pb.AuthoriseReply, error) {
	mac, err := net.ParseMAC(r.Mac)
	if err != nil {
		return nil, fmt.Errorf("invalid MAC %q: %v", mac, err)
	}

	if err := s.d.SetInterfaceForMAC(mac, r.Interface); err != nil {
		return nil, err
	}

	return &pb.AuthoriseReply{
		Interface: r.Interface,
		Mac:       r.Mac,
	}, nil
}

func main() {
	flag.Parse()

	log.Println("macvland starting up")
	log.Printf("interfaces: %v", *flagInterfaces)
	log.Printf("addr: %v", *flagAddr)

	var intfs []string
	if *flagInterfaces != "" {
		intfs = strings.Split(*flagInterfaces, ",")
	} else {
		log.Printf("watching all interfaces")
	}

	mdb := macDB{Interfaces: intfs}
	if err := mdb.Run(); err != nil {
		log.Fatalf("failed to watch interfaces: %v", err)
	}
	defer mdb.Stop()

	lis, err := net.Listen("tcp", *flagAddr)
	if err != nil {
		log.Fatalf("failed to net.Listen(%v): %v", *flagAddr, err)
	}

	s := grpc.NewServer()
	serv := &server{d: &mdb}
	pb.RegisterMACVLANServer(s, serv)
	reflection.Register(s)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
