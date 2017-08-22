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
	"net"
	"sync"

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

	unknownVLAN     = 201
	guestVLAN       = 200
	vlanToInterface = map[int]string{
		100: "mv100",
		101: "mv101",
		102: "mv102",
		103: "mv103",
		200: "mv200",
		201: "mv201",
	}
)

type server struct {
	mvln       pb.MACVLANClient
	mu         sync.Mutex
	macsToVLAN map[string]int
}

func (s *server) SawClient(ctx context.Context, req *pb.SawClientRequest) (*pb.SawClientReply, error) {
	// assign to captive VLAN
	log.Printf("SawClient: MAC=%v", req.Mac)

	s.mu.Lock()
	vlanToAssign, ok := s.macsToVLAN[req.Mac]
	s.mu.Unlock()

	if !ok {
		vlanToAssign = unknownVLAN
	}

	_, err := s.mvln.Authorise(ctx, &pb.AuthoriseRequest{
		Interface: vlanToInterface[vlanToAssign],
		Mac:       req.Mac,
	})
	if err != nil {
		log.Printf("SawClient: error Authorising %v onto unknownVLAN %v: %v", req.Mac, unknownVLAN, err)
		return nil, err
	}
	return &pb.SawClientReply{}, nil
}

func (s *server) ClientAuthenticated(ctx context.Context, req *pb.ClientAuthenticatedRequest) (*pb.ClientAuthenticatedReply, error) {
	// assign to default VLAN
	// TODO: actual logic
	s.mu.Lock()
	s.macsToVLAN[req.Mac] = guestVLAN
	s.mu.Unlock()

	log.Printf("ClientAuthenticated: MAC=%v; Email=%v", req.Mac, req.Email)
	_, err := s.mvln.Authorise(ctx, &pb.AuthoriseRequest{
		Interface: vlanToInterface[guestVLAN],
		Mac:       req.Mac,
	})
	if err != nil {
		log.Printf("ClientAuthenticated: error Authorising %v onto %v: %v", req.Mac, guestVLAN, err)
		return nil, err
	}
	return &pb.ClientAuthenticatedReply{}, nil
}

func main() {
	flag.Parse()

	log.Println("captivated starting up")
	log.Printf("addr: %v", *flagAddr)
	log.Printf("macvland-addr: %v", *flagMACVLANAddr)

	mvconn, err := grpc.Dial(*flagMACVLANAddr, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("grpc.Dial(%v): %v", *flagMACVLANAddr, err)
	}
	mvln := pb.NewMACVLANClient(mvconn)

	lis, err := net.Listen("tcp", *flagAddr)
	if err != nil {
		log.Fatalf("failed to net.Listen(%v): %v", *flagAddr, err)
	}

	s := grpc.NewServer()
	serv := &server{
		mvln:       mvln,
		macsToVLAN: make(map[string]int),
	}
	pb.RegisterCaptivateServer(s, serv)
	reflection.Register(s)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
