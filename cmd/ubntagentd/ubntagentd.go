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
	"flag"
	"log"
	"log/syslog"
	"net"
	"os"

	"google.golang.org/grpc"

	pb "github.com/lukegb/captivate/captivated"
	"golang.org/x/net/context"
)

var (
	captivated pb.CaptivateClient

	flagCaptivatedAddr = flag.String("captivated-addr", "[::1]:21000", "address to connect to captivated on")

	flagLogToStderr = flag.Bool("log-to-stderr", false, "log to stderr instead of syslog")

	flagHostapdSocketDir = flag.String("hostapd-socket-dir", "/var/run/hostapd", "socket location for hostapd control sockets")

	flagRadiusAddr   = flag.String("radius-listen", "127.0.0.1:1812", "address to listen on for RADIUS authentication requests")
	flagRadiusSecret = flag.String("radius-secret", "testing123", "RADIUS secret")
)

func main() {
	flag.Parse()

	if !*flagLogToStderr {
		logw, err := syslog.Dial("unixgram", "/dev/log", syslog.LOG_WARNING|syslog.LOG_DAEMON, "ubntagentd")
		if err != nil {
			log.Println("failed to open syslog: %v", err)
			os.Exit(1)
		}
		log.SetOutput(logw)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	captivatedConn, err := grpc.Dial(*flagCaptivatedAddr, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("grpc.Dial(%v): %v", *flagCaptivatedAddr, err)
	}

	c := pb.NewCaptivateClient(captivatedConn)

	hostapConn := hostap(c)

	radiusConn, err := net.ListenPacket("udp", *flagRadiusAddr)
	if err != nil {
		log.Fatalf("radius: listen on %v: %v", *flagRadiusAddr, err)
	}
	log.Printf("radius: listening for requests on %v", radiusConn.LocalAddr())

	go radiusServer(ctx, radiusConn, radiusOptions{Captivate: c, Secret: []byte(*flagRadiusSecret)})
	go vlanWatcher(c, hostapConn)
	<-chan struct{}(nil)
}
