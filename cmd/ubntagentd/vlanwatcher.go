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
	"log"
	"net"
	"time"

	pb "github.com/lukegb/captivate/captivated"
	"github.com/lukegb/captivate/ubiquiti"
)

func vlanHandleChange(ch *pb.VLANAssignmentChange, w *hostapWatcher) {
	mac, err := net.ParseMAC(ch.Mac)
	if err != nil {
		log.Printf("vlanwatcher: failed to parse %v as MAC: %v", mac, err)
		return
	}

	if err := ubiquiti.SetVLAN(mac, ch.Vlan); err != nil {
		log.Printf("vlanwatcher: failed to set %v to VLAN %d: %v", mac, ch.Vlan, err)
	}

	if err := w.VLANChanged(mac); err != nil {
		log.Printf("vlanwatcher: hostapd returned error: %v", err)
	}
}

func vlanWatcher(c pb.CaptivateClient, w *hostapWatcher) {
	ctx := context.Background()
outer:
	for {
		cli, err := c.WatchVLANAssignmentChange(ctx, &pb.WatchVLANAssignmentChangeRequest{})
		if err != nil {
			log.Printf("vlanwatcher: WatchVLANAssignmentChange: %v", err, err)
			time.Sleep(10 * time.Second)
			continue outer
		}
		log.Printf("vlanwatcher: ready")

		for {
			ch, err := cli.Recv()
			if err != nil {
				log.Printf("vlanwatcher: %v", err)
				time.Sleep(10 * time.Second)
				continue outer
			}

			log.Printf("vlanwatcher: informed of change: %v", ch)
			vlanHandleChange(ch, w)
		}
	}
}
