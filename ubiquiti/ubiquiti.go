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

// Package ubiquiti implements some dark low-level magic related to Ubiqiti APs.
package ubiquiti

import (
	"fmt"
	"log"
	"net"
	"strings"
	"syscall"
	"unsafe"
)

type IoctlStruct struct {
	Iface    [0x10]byte
	InsnLo   uint16
	InsnHi   uint16
	MAC      [0x6]uint8
	VLANIDHi uint16
	VLANIDLo uint16
}

const (
	ioctl_80211setparam = 0x8BE0
	setparam_VLAN32     = 0x18e
)

func setVLAN(fd int, intf string, mac net.HardwareAddr, vlanID uint32) error {
	f := IoctlStruct{
		InsnLo: uint16((setparam_VLAN32 & 0xffff0000) >> 16),
		InsnHi: uint16(setparam_VLAN32 & 0xffff),

		VLANIDHi: uint16((vlanID & 0xffff0000) >> 16),
		VLANIDLo: uint16(vlanID & 0xffff),
	}

	copy(f.Iface[:], []byte(intf))
	f.Iface[len(intf)] = 0x0

	copy(f.MAC[:], mac)

	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), ioctl_80211setparam, uintptr(unsafe.Pointer(&f.Iface)))
	if err == 0 {
		return nil
	}
	return err
}

// SetVLANOnInterface uses the undocumented Ubiquiti ioctl implemented in recent Gen2 APs to set the 802.1q VLAN for a specific MAC.
func SetVLANOnInterface(intf string, mac net.HardwareAddr, vlanID uint32) error {
	// open raw
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("opening inet socket: %v", err)
	}
	defer syscall.Close(fd)

	return setVLAN(fd, intf, mac, vlanID)
}

// SetVLAN sets MAC to VLAN on all ath interfaces.
func SetVLAN(mac net.HardwareAddr, vlanID uint32) error {
	// open raw
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("opening inet socket: %v", err)
	}
	defer syscall.Close(fd)

	// enumerate interfaces
	intfs, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("enumerating interfaces: %v", err)
	}

	for _, intf := range intfs {
		if intf.Flags&net.FlagUp != net.FlagUp {
			continue
		}
		if !strings.HasPrefix(intf.Name, "ath") {
			continue
		}

		if setErr := setVLAN(fd, intf.Name, mac, vlanID); setErr != nil {
			log.Printf("ubiquiti: setting VLAN on %s for %s to %d failed: %v", intf.Name, mac, vlanID)
			err = setErr
			// keep going, regardless
		}
	}
	return err
}
