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

package tls

import (
	"fmt"
	"io"
)

func readRecord(r io.Reader, contentType uint8) ([]byte, error) {
	head := make([]byte, 5)
	if n, err := r.Read(head); err != nil {
		return nil, err
	} else if n != 5 {
		return nil, fmt.Errorf("read %d bytes, wanted %d", n, 5)
	}

	if head[0] != contentType {
		return nil, fmt.Errorf("unexpected content type %d, wanted %d", head[0], contentType)
	}

	ln := uint16(head[3])<<8 | uint16(head[4])
	fragment := make([]byte, ln)
	if n, err := r.Read(fragment); err != nil {
		return nil, err
	} else if n != int(ln) {
		return nil, fmt.Errorf("read %d bytes of fragment, wanted %d", n, ln)
	}

	return fragment, nil
}
