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
	flagAddr        = flag.String("addr", "[::1]:21000", "address to listen for gRPC requests on")
	flagMACVLANAddr = flag.String("macvland-addr", "[::1]:21001", "address to connect to macvland on")
	flagDatabase    = flag.String("db-conn", "user=captivated dbname=captivated sslmode=disable", "database connection string")
)

type server struct {
	mvln pb.MACVLANClient
	db   *Database
}

func (s *server) SawClient(ctx context.Context, req *pb.SawClientRequest) (*pb.SawClientReply, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	mac, err := net.ParseMAC(req.Mac)
	if err != nil {
		log.Printf("SawClient rejected MAC %v: %v", req.Mac, err)
		return nil, fmt.Errorf("invalid MAC %v", req.Mac)
	}

	log.Printf("SawClient: MAC=%v; macvlan is pending", mac)
	mvlan, err := s.db.GetMACVLANInterfaceForDevice(ctx, mac)
	if err != nil {
		log.Printf("SawClient got error from GetMACVLANInterfaceForDevice(%v): %v", mac, err)
		return nil, fmt.Errorf("GetMACVLANInterfaceForDevice(%v): %v", mac, err)
	}

	err = s.db.MarkDeviceSeen(ctx, mac)
	if err != nil {
		log.Printf("SawClient got error from MarkDeviceSeen(%v): %v; carrying on anyway", mac, err)
	}

	log.Printf("SawClient: MAC=%v; macvlan=%v", mac, mvlan)

	_, err = s.mvln.Authorise(ctx, &pb.AuthoriseRequest{
		Interface: mvlan,
		Mac:       mac.String(),
	})
	if err != nil {
		log.Printf("SawClient got error from Authorise %v onto %v: %v", req.Mac, mvlan, err)
		return nil, err
	}
	return &pb.SawClientReply{}, nil
}

func (s *server) ClientAuthenticated(ctx context.Context, req *pb.ClientAuthenticatedRequest) (*pb.ClientAuthenticatedReply, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	mac, err := net.ParseMAC(req.Mac)
	if err != nil {
		log.Printf("ClientAuthenticated rejected MAC %v: %v", req.Mac, err)
		return nil, fmt.Errorf("invalid MAC %v", req.Mac)
	}

	log.Printf("ClientAuthenticated: MAC=%v; Email=%v; macvlan is pending", mac, req.Email)

	err = s.db.SetUserForDevice(ctx, mac, req.Email)
	if err != nil {
		log.Printf("ClientAuthenticated got error from SetUserForDevice(%v, %v): %v", mac, req.Email, err)
		return nil, err
	}

	err = s.db.MarkDeviceSeen(ctx, mac)
	if err != nil {
		log.Printf("ClientAuthenticated got error from MarkDeviceSeen(%v): %v; carrying on anyway", mac, err)
	}

	mvlan, err := s.db.GetMACVLANInterfaceForDevice(ctx, mac)
	if err != nil {
		log.Printf("ClientAuthenticated got error from GetMACVLANInterfaceForDevice(%v): %v", mac, err)
		return nil, fmt.Errorf("GetMACVLANInterfaceForDevice(%v): %v", mac, err)
	}

	log.Printf("ClientAuthenticated: MAC=%v; Email=%v; macvlan=%v", mac, req.Email, mvlan)

	_, err = s.mvln.Authorise(ctx, &pb.AuthoriseRequest{
		Interface: mvlan,
		Mac:       mac.String(),
	})
	if err != nil {
		log.Printf("ClientAuthenticated: error Authorise %v onto %v: %v", req.Mac, mvlan, err)
		return nil, err
	}
	return &pb.ClientAuthenticatedReply{}, nil
}

func main() {
	flag.Parse()

	log.Println("captivated starting up")
	log.Printf("addr: %v", *flagAddr)
	log.Printf("macvland-addr: %v", *flagMACVLANAddr)
	log.Printf("db-conn: %v", *flagDatabase)

	mvconn, err := grpc.Dial(*flagMACVLANAddr, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("grpc.Dial(%v): %v", *flagMACVLANAddr, err)
	}
	mvln := pb.NewMACVLANClient(mvconn)

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
		mvln: mvln,
		db:   db,
	}
	pb.RegisterCaptivateServer(s, serv)
	reflection.Register(s)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
