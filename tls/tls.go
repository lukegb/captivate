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

const (
	maxMessageLength = 65536 // same as maxMessageLength from crypto/tls

	contentTypeAlert     uint8 = 21
	contentTypeHandshake uint8 = 22

	alertLevelFatal uint8 = 2

	handshakeTypeClientHello uint8 = 1

	alertInternalError    uint8 = 80
	alertUnrecognizedName uint8 = 112

	extensionServerName uint16 = 0
)

type ProtocolVersion struct {
	Major, Minor uint8
}

type ClientHello struct {
	ProtocolVersion ProtocolVersion
	ServerName      string
}

func readClientHello(r io.Reader) (hi *ClientHello, err error) {
	buf, err := readRecord(r, contentTypeHandshake)
	if err != nil {
		return nil, err
	}
	// read message length
	if buf[0] != handshakeTypeClientHello {
		return nil, tlsErrorf(alertInternalError, "expected handshake type ClientHello (%d), got %d", handshakeTypeClientHello, buf[0])
	}
	msgLen := int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
	if msgLen > maxMessageLength {
		return nil, tlsErrorf(alertInternalError, "handshake message of length %d bytes exceeds maximum of %d bytes", msgLen, maxMessageLength)
	}

	for len(buf) < 4+msgLen {
		fmt.Println(len(buf))
		nbuf, err := readRecord(r, contentTypeHandshake)
		if err != nil {
			return nil, err
		}
		buf = append(buf, nbuf...)
	}

	hi = &ClientHello{}
	hi.ProtocolVersion.Major = buf[4]
	hi.ProtocolVersion.Minor = buf[5]
	if hi.ProtocolVersion.Major < 3 || (hi.ProtocolVersion.Major == 3 && hi.ProtocolVersion.Minor < 3) {
		return nil, fmt.Errorf("client offered version %d, %d which is less than our minimum of 3, 3", hi.ProtocolVersion.Major, hi.ProtocolVersion.Minor)
	}

	// skip session ID
	sessionIdLen := int(buf[38])
	if sessionIdLen < 0 || sessionIdLen > 32 || len(buf) < 39+sessionIdLen {
		return nil, fmt.Errorf("sessionIdLen was %d, out of range! min=0, max=32, datamax=%d", sessionIdLen, len(buf)-39)
	}
	buf = buf[39+sessionIdLen:]
	if len(buf) < 2 {
		return nil, fmt.Errorf("insufficient data in buffer after trimming session ID, have %d bytes", len(buf))
	}

	// skip cipher suites
	cipherSuiteLen := int(buf[0])<<16 | int(buf[1])
	if cipherSuiteLen%2 == 1 || len(buf) < 2+cipherSuiteLen {
		return nil, fmt.Errorf("cipherSuiteLen was %d; either not even or buffer too short", cipherSuiteLen)
	}
	buf = buf[2+cipherSuiteLen:]

	// skip compression methods
	compressionMethodsLen := int(buf[0])
	if len(buf) < 1+compressionMethodsLen {
		return nil, fmt.Errorf("compressionMethodsLen was %d; buffer too short", compressionMethodsLen)
	}
	buf = buf[1+compressionMethodsLen:]

	if len(buf) == 0 {
		// no extensions
		return hi, nil
	}
	if len(buf) < 2 {
		return nil, fmt.Errorf("buf too short when parsing extensions")
	}

	extensionsLength := int(buf[0])<<8 | int(buf[1])
	buf = buf[2:]
	if extensionsLength != len(buf) {
		return nil, fmt.Errorf("mismatch in claimed length of extensions (%d) vs. length of buffer (%d)", extensionsLength, len(buf))
	}

	for len(buf) != 0 {
		if len(buf) < 4 {
			return nil, fmt.Errorf("not enough bytes left to parse an extension; len(buf) = %d", len(buf))
		}
		extension := uint16(buf[0])<<8 | uint16(buf[1])
		length := int(buf[2])<<8 | int(buf[3])
		buf = buf[4:]
		if len(buf) < length {
			return nil, fmt.Errorf("claimed length of extension (%d) is larger than remaining buffer (%d)", length, len(buf))
		}

		extbuf := buf[:length]
		buf = buf[length:]
		if extension != extensionServerName {
			// ignore
			continue
		}

		// server name indication!
		serverNameCount := uint16(extbuf[0])<<8 | uint16(extbuf[1])
		extbuf = extbuf[2:]
		if len(extbuf) != int(serverNameCount) {
			return nil, fmt.Errorf("serverNameCount (%d) doesn't match extension length (%d)", serverNameCount, len(extbuf))
		}
		for len(extbuf) > 0 {
			if len(extbuf) < 3 {
				return nil, fmt.Errorf("serverName, not enough bytes to read name")
			}
			nameType := int(extbuf[0])
			if nameType != 0 {
				return nil, tlsErrorf(alertUnrecognizedName, "unsupported name_type %d", nameType)
			}

			nameLen := uint16(extbuf[1])<<8 | uint16(extbuf[2])
			extbuf = extbuf[3:]
			hi.ServerName = string(extbuf[:nameLen])
			if len(extbuf) < int(nameLen) {
				return nil, fmt.Errorf("not enough bytes (buffer has %d) to read server_name of %d bytes", len(extbuf), nameLen)
			}
			extbuf = extbuf[nameLen:]
		}
	}

	return hi, nil
}

func sendTLSAlert(w io.Writer, alert uint8) error {
	abuf := make([]byte, 7)
	abuf[0] = contentTypeAlert

	// set protocolversion
	abuf[1] = 3
	abuf[2] = 1

	// set length of payload
	abuf[3] = 0
	abuf[4] = 2

	abuf[5] = alertLevelFatal
	abuf[6] = alert

	_, err := w.Write(abuf)
	return err
}
