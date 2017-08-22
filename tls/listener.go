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
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/lukegb/fourtosix"
)

type Listener struct {
	RemotePort int

	ProxyHostnames   []string
	AllowedHostnames []string

	ln        net.Listener
	queueLock sync.Mutex
	queue     chan net.Conn
}

type connWrap struct {
	preBuf []byte
	c      net.Conn
}

func (c *connWrap) Read(b []byte) (n int, err error) {
	if c.preBuf != nil {
		n = copy(b, c.preBuf)
		c.preBuf = c.preBuf[n:]
		if len(c.preBuf) == 0 {
			// there are no more bytes in our preBuf
			c.preBuf = nil
		}
		return n, nil
	}

	return c.c.Read(b[n:])
}
func (c *connWrap) Write(b []byte) (int, error)        { return c.c.Write(b) }
func (c *connWrap) Close() error                       { return c.c.Close() }
func (c *connWrap) LocalAddr() net.Addr                { return c.c.LocalAddr() }
func (c *connWrap) RemoteAddr() net.Addr               { return c.c.RemoteAddr() }
func (c *connWrap) SetDeadline(t time.Time) error      { return c.c.SetDeadline(t) }
func (c *connWrap) SetReadDeadline(t time.Time) error  { return c.c.SetReadDeadline(t) }
func (c *connWrap) SetWriteDeadline(t time.Time) error { return c.c.SetWriteDeadline(t) }

func (l *Listener) handleTLS(conn net.Conn) {
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	log.Printf("[%s] got connection", conn.RemoteAddr())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mr := &memorizingReader{r: conn}
	hi, err := readClientHello(mr)
	if err != nil {
		log.Printf("[%s] readClientHello: %v", conn.RemoteAddr(), err)
		alert := alertInternalError
		if tlsErr, ok := err.(*tlsError); ok {
			alert = tlsErr.alert
		}
		sendTLSAlert(conn, alert)
		conn.Close()
		return
	}
	if hi.ServerName == "" {
		log.Printf("[%s] no server_name", conn.RemoteAddr())
		sendTLSAlert(conn, alertUnrecognizedName)
		conn.Close()
		return
	}

	log.Printf("[%s] hooray, it's to %q", conn.RemoteAddr(), hi.ServerName)

	isAllowedProxy := false
	isAllowedHandoff := false
	for _, n := range l.ProxyHostnames {
		if n == hi.ServerName {
			isAllowedProxy = true
			break
		}
	}
	for _, n := range l.AllowedHostnames {
		if n == hi.ServerName {
			isAllowedHandoff = true
			break
		}
	}

	if isAllowedHandoff {
		log.Printf("[%s] handing off to net/http", conn.RemoteAddr())
		cw := &connWrap{
			preBuf: mr.buf,
			c:      conn,
		}
		l.queue <- cw
		log.Printf("[%s] %q delivered onto queue", conn.RemoteAddr(), hi.ServerName)
		return
	}
	if !isAllowedProxy {
		log.Printf("[%s] bad hostname %v, dropping connection", conn.RemoteAddr(), hi.ServerName)
		sendTLSAlert(conn, alertUnrecognizedName)
		conn.Close()
		return
	}

	defer conn.Close()
	rport := l.RemotePort
	if rport == 0 {
		rport = 443
	}

	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}

	rconn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(hi.ServerName, fmt.Sprintf("%d", rport)))
	if err != nil {
		log.Printf("[%s] connect %s: %v", conn.RemoteAddr(), hi.ServerName, err)
		sendTLSAlert(conn, alertUnrecognizedName)
		return
	}
	defer rconn.Close()
	log.Printf("[%s] connected to %s", conn.RemoteAddr(), hi.ServerName)
	if _, err := rconn.Write(mr.buf); err != nil {
		log.Printf("[%s] write ClientHello to rconn %s: %v", conn.RemoteAddr(), hi.ServerName, err)
		sendTLSAlert(conn, alertInternalError)
		return
	}

	// unset deadline
	var zero time.Time
	conn.SetDeadline(zero)

	log.Printf("[%s] gluing connections together", conn.RemoteAddr())
	fourtosix.Glue(conn, rconn)
	log.Printf("[%s] closing connection", conn.RemoteAddr())
}

func (l *Listener) ensureQueue() {
	l.queueLock.Lock()
	if l.queue == nil {
		l.queue = make(chan net.Conn)
	}
	l.queueLock.Unlock()
}

func (l *Listener) Listen(network, addr string) error {
	ln, err := net.Listen(network, addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}
	l.ln = ln
	l.ensureQueue()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept: %v", err)
		}
		go l.handleTLS(conn)
	}
}

func (l *Listener) Accept() (net.Conn, error) {
	l.ensureQueue()
	for x := range l.queue {
		return x, nil
	}
	return nil, fmt.Errorf("listener closed")
}

func (l *Listener) Close() error {
	l.ensureQueue()
	if err := l.ln.Close(); err != nil {
		return err
	}
	close(l.queue)
	l.queue = nil
	return nil
}

func (l *Listener) Addr() net.Addr {
	return l.ln.Addr()
}
