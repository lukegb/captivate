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

// Package hostapd implements communicating with hostapd over its control socket.
package hostapd

import (
	"io/ioutil"
	"os"
)

const (
	HostapdSocketDirectory = "/var/run/hostapd"
)

// ListTransports lists the sockets available in the hostapd directory.
func ListTransports(dir string) ([]string, error) {
	if dir == "" {
		dir = HostapdSocketDirectory
	}

	dents, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var socks []string
	for _, dent := range dents {
		if dent.Mode()&os.ModeSocket != os.ModeSocket {
			continue
		}
		socks = append(socks, dent.Name())
	}

	return socks, nil
}
