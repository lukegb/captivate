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
	ctls "crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"google.golang.org/grpc"

	rice "github.com/GeertJohan/go.rice"
	pb "github.com/lukegb/captivate/captivated"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/lukegb/captivate/tls"
)

var (
	captivated pb.CaptivateClient

	flagCaptivatedAddr = flag.String("captivated-addr", "[::1]:21000", "address to connect to captivated on")
	flagClientID       = flag.String("oauth-client-id", "", "OAuth Client ID for Google login")
	flagClientSecret   = flag.String("oauth-client-secret", "", "OAuth Client Secret for Google login")

	flagHostnames      = flag.String("hostnames", "captive.house.as205479.net,v4-captive.house.as205479.net,v6-captive.house.as205479.net", "hostnames to listen for")
	flagProxyHostnames = flag.String("proxy-hostnames", "apis.google.com,accounts.google.com,accounts.google.co.uk,accounts.youtube.com,www.googleapis.com,ssl.gstatic.com,lh3.googleusercontent.com", "TLS SNI hostnames to allow access to through the proxy")
	flagRedirectURL    = flag.String("oauth-redirect-url", "https://captive.house.as205479.net/oauth2callback", "redirect URL for oauth")

	flagTLSCert = flag.String("tls-cert", "/etc/letsencrypt/live/captive.house.as205479.net/fullchain.pem", "TLS certificate chain location")
	flagTLSKey  = flag.String("tls-key", "/etc/letsencrypt/live/captive.house.as205479.net/privkey.pem", "TLS private key location")

	flagListenAddr = flag.String("addr", "[2a07:1c44:3636:201::1337]:443,172.27.201.1:443", "comma-separated addresses to listen on")
)

func isDone(remoteAddr string) (bool, error) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false, err
	}

	return !strings.HasPrefix(host, "2a07:1c44:3636:201:") && !strings.HasPrefix(host, "172.27.201."), nil
}

func listen(n string, tc *ctls.Config) {
	log.Printf("listening for connections on %v", n)
	l := &tls.Listener{
		RemotePort:       443,
		AllowedHostnames: strings.Split(*flagHostnames, ","),
		ProxyHostnames:   strings.Split(*flagProxyHostnames, ","),
	}
	go http.Serve(ctls.NewListener(l, tc), nil)
	log.Fatal(l.Listen("tcp", n))
}

func authorizeMAC(ctx context.Context, mac net.HardwareAddr, email string) error {
	log.Printf("waiting to authorise %s by %v", mac.String(), email)
	go func() {
		// give it a bit...
		time.Sleep(1 * time.Second)
		log.Printf("authorising %s by %v", mac.String(), email)
		_, err := captivated.ClientAuthenticated(context.Background(), &pb.ClientAuthenticatedRequest{
			Mac:   mac.String(),
			Email: email,
		})
		if err != nil {
			log.Printf("failed to send ClientAuthenticated for %v: %v", mac.String(), err)
		}
	}()
	return nil
}

func getMAC(ctx context.Context, remoteIP string) (net.HardwareAddr, error) {
	ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	stdout, err := exec.CommandContext(ctx, "/usr/bin/ip", "neigh", "show", "to", remoteIP).Output()
	if err != nil {
		return nil, err
	}

	r := regexp.MustCompile(`^(?:[0-9.]+|[0-9a-f:]+) dev [a-z0-9.]+ lladdr ((?:[0-9a-f]{2}:){5}[0-9a-f]{2}) `)
	bits := r.FindSubmatch(stdout)
	if bits == nil {
		return nil, fmt.Errorf("failed to match neighbor table for %v - got %v", remoteIP, string(stdout))
	}

	return net.ParseMAC(string(bits[1]))
}

func main() {
	flag.Parse()

	log.Println("capauthd starting up")

	log.Printf("loading TLS certificate from %v", *flagTLSCert)
	cert, err := ctls.LoadX509KeyPair(*flagTLSCert, *flagTLSKey)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("connecting to captivated on %v", *flagCaptivatedAddr)
	conn, err := grpc.Dial(*flagCaptivatedAddr, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("grpc.Dial(%v): %v", *flagCaptivatedAddr, err)
	}

	captivated = pb.NewCaptivateClient(conn)

	tc := &ctls.Config{Certificates: []ctls.Certificate{cert}}

	log.Printf("using oauth2 client ID %v", *flagClientID)
	conf := &oauth2.Config{
		ClientID:     *flagClientID,
		ClientSecret: *flagClientSecret,
		RedirectURL:  *flagRedirectURL,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}

	log.Printf("loading resources")
	templateBox, err := rice.FindBox("templates")
	if err != nil {
		log.Fatalf("failed to find `templates`: %v", err)
	}

	templates := make(map[string]*template.Template)
	templateBox.Walk("", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		tplStr, err := templateBox.String(path)
		if err != nil {
			log.Printf("failed to read %q: %v", path, err)
			return err
		}
		tpl, err := template.New(path).Parse(tplStr)
		if err != nil {
			log.Printf("failed to parse %q: %v", path, err)
			return err
		}
		templates[path] = tpl
		return nil
	})

	staticBox, err := rice.FindBox("static")
	if err != nil {
		log.Fatalf("failed to find `static`: %v", err)
	}
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(staticBox.HTTPBox())))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.Error(w, "page not found", http.StatusNotFound)
			return
		}

		done, err := isDone(r.RemoteAddr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if done {
			w.Header().Set("Location", "https://as205479.net")
			w.WriteHeader(http.StatusTemporaryRedirect)
			fmt.Fprintf(w, "Redirecting...")
			return
		}

		d := struct {
			Next     string
			ClientID string
		}{
			Next:     r.URL.Query().Get("next"),
			ClientID: *flagClientID,
		}

		if err := templates["index.html"].Execute(w, d); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	http.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// generate a state
		mac, err := getMAC(ctx, host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		loginURL := conf.AuthCodeURL(mac.String())
		w.Header().Set("Location", loginURL)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusTemporaryRedirect)
		fmt.Fprintf(w, "<a href=\"%s\">Redirecting...</a>", loginURL)
	})
	http.HandleFunc("/isdone", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://captive.house.as205479.net")
		w.Header().Set("Access-Control-Allow-Methods", "GET")

		done, err := isDone(r.RemoteAddr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		v := struct {
			OK bool `json:"ok"`
		}{done}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	})
	stateCodeMap := make(map[string]bool)
	http.HandleFunc("/oauth2callback", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if r.URL.Path != "/oauth2callback" {
			http.Error(w, "page not found", http.StatusNotFound)
			return
		}
		if r.Method != "GET" {
			w.Header().Set("Allow", "GET")
			http.Error(w, "must be a GET", http.StatusMethodNotAllowed)
			return
		}

		done, err := isDone(r.RemoteAddr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if done {
			w.Header().Set("Location", "https://as205479.net")
			w.WriteHeader(http.StatusTemporaryRedirect)
			fmt.Fprintf(w, "Redirecting...")
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		mac, err := getMAC(ctx, host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		sentState := r.URL.Query().Get("state")
		sentCode := r.URL.Query().Get("code")
		if sentState != mac.String() {
			log.Printf("client sent bad state: MAC is %q, but state was %q", mac, sentState)
			http.Error(w, "bad session state", http.StatusBadRequest)
			return
		}

		scmKey := fmt.Sprintf("%s!!%s", sentState, sentCode)
		if !stateCodeMap[scmKey] {
			stateCodeMap[scmKey] = true

			tok, err := conf.Exchange(ctx, r.URL.Query().Get("code"))
			if err != nil {
				log.Printf("failed to exchange oauth token for %v: %v", mac, err)
				http.Error(w, "bad oauth token", http.StatusBadRequest)
				return
			}

			client := conf.Client(ctx, tok)
			resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
			if err != nil {
				log.Printf("failed to retrieve userinfo for %v: %v", mac, err)
				http.Error(w, fmt.Sprintf("google userinfo API failed: %v", err), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()

			type Data struct {
				Email         string `json:"email"`
				EmailVerified bool   `json:"email_verified"`
			}
			var d Data
			if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
				log.Printf("failed to decode userinfo for %v: %v", mac, err)
				http.Error(w, fmt.Sprintf("google userinfo API returned garbage: %v", err), http.StatusBadGateway)
				return
			}

			if !d.EmailVerified {
				log.Printf("google says %v does not have verified email (MAC: %q)", d.Email, mac)
				http.Error(w, fmt.Sprintf("user %v does not have verified email", d.Email), http.StatusBadRequest)
				return
			}

			if err := authorizeMAC(ctx, mac, d.Email); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}

		next := r.URL.Query().Get("next")
		if next == "" {
			next = "https://as205479.net"
		}

		d2 := struct {
			Next string
		}{next}
		if err := templates["pleasewait.html"].Execute(w, d2); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	laddr := strings.Split(*flagListenAddr, ",")
	for _, n := range laddr[:len(laddr)-1] {
		go listen(n, tc)
	}
	listen(laddr[len(laddr)-1], tc)
}
