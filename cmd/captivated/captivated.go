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
	"database/sql"
	"fmt"
	"net"
	"sync"
	"time"

	_ "github.com/lib/pq"
	pb "github.com/lukegb/captivate/captivated"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"flag"
	"log"
)

var (
	flagAddr     = flag.String("addr", "[::1]:21000", "address to listen for gRPC requests on")
	flagDatabase = flag.String("db-conn", "user=captivated dbname=captivated sslmode=disable", "database connection string")
)

type server struct {
	db *Database

	watchMu  sync.Mutex
	watchers []chan *pb.VLANAssignmentChange
}

func (s *server) SawClient(ctx context.Context, req *pb.SawClientRequest) (*pb.SawClientReply, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	mac, err := net.ParseMAC(req.Mac)
	if err != nil {
		log.Printf("SawClient rejected MAC %v: %v", req.Mac, err)
		return nil, fmt.Errorf("invalid MAC %v", req.Mac)
	}

	log.Printf("SawClient: MAC=%v; VLAN is pending", mac)
	vlanID, err := s.db.GetVLANForDevice(ctx, mac)
	if err != nil {
		log.Printf("SawClient got error from GetVLANForDevice(%v): %v", mac, err)
		return nil, fmt.Errorf("GetVLANForDevice(%v): %v", mac, err)
	}

	err = s.db.MarkDeviceSeen(ctx, mac)
	if err != nil {
		log.Printf("SawClient got error from MarkDeviceSeen(%v): %v; carrying on anyway", mac, err)
	}

	log.Printf("SawClient: MAC=%v; vlan=%v", mac, vlanID)

	return &pb.SawClientReply{
		Vlan: vlanID,
	}, nil
}

func (s *server) ClientAuthenticated(ctx context.Context, req *pb.ClientAuthenticatedRequest) (*pb.ClientAuthenticatedReply, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	mac, err := net.ParseMAC(req.Mac)
	if err != nil {
		log.Printf("ClientAuthenticated rejected MAC %v: %v", req.Mac, err)
		return nil, fmt.Errorf("invalid MAC %v", req.Mac)
	}

	log.Printf("ClientAuthenticated: MAC=%v; Email=%v; vlan is pending", mac, req.Email)

	err = s.db.SetUserForDevice(ctx, mac, req.Email)
	if err != nil {
		log.Printf("ClientAuthenticated got error from SetUserForDevice(%v, %v): %v", mac, req.Email, err)
		return nil, err
	}

	err = s.db.MarkDeviceSeen(ctx, mac)
	if err != nil {
		log.Printf("ClientAuthenticated got error from MarkDeviceSeen(%v): %v; carrying on anyway", mac, err)
	}

	vlanID, err := s.db.GetVLANForDevice(ctx, mac)
	if err != nil {
		log.Printf("ClientAuthenticated got error from GetVLANForDevice(%v): %v", mac, err)
		return nil, fmt.Errorf("GetVLANForDevice(%v): %v", mac, err)
	}

	log.Printf("ClientAuthenticated: MAC=%v; Email=%v; vlan=%v", mac, req.Email, vlanID)
	s.watchMu.Lock()
	vac := pb.VLANAssignmentChange{
		Mac:  mac.String(),
		Vlan: vlanID,
	}
	for _, w := range s.watchers {
		w <- &vac
	}
	s.watchMu.Unlock()

	return &pb.ClientAuthenticatedReply{}, nil
}

func (s *server) WatchVLANAssignmentChange(req *pb.WatchVLANAssignmentChangeRequest, stream pb.Captivate_WatchVLANAssignmentChangeServer) error {
	ch := make(chan *pb.VLANAssignmentChange)
	s.watchMu.Lock()
	s.watchers = append(s.watchers, ch)
	s.watchMu.Unlock()
	defer func() {
		s.watchMu.Lock()
		newWatchers := make([]chan *pb.VLANAssignmentChange, 0, len(s.watchers)-1)
		for _, w := range s.watchers {
			if w != ch {
				newWatchers = append(newWatchers, w)
			}
		}
		s.watchers = newWatchers
		s.watchMu.Unlock()
	}()

	for change := range ch {
		if err := stream.Send(change); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	flag.Parse()

	log.Println("captivated starting up")
	log.Printf("addr: %v", *flagAddr)
	log.Printf("db-conn: %v", *flagDatabase)

	lis, err := net.Listen("tcp", *flagAddr)
	if err != nil {
		log.Fatalf("failed to net.Listen(%v): %v", *flagAddr, err)
	}

	dbc, err := sql.Open("postgres", *flagDatabase)
	if err != nil {
		log.Fatalf("sql.Open(\"postgres\", %q): %v", *flagDatabase, err)
	}

	db, err := NewDatabase(context.Background(), dbc)
	if err != nil {
		log.Fatalf("NewDatabase: %v", err)
	}

	s := grpc.NewServer()
	serv := &server{
		db: db,
	}
	pb.RegisterCaptivateServer(s, serv)
	reflection.Register(s)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
