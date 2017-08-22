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
	"os/exec"
	"regexp"
	"strings"
	"time"

	"google.golang.org/grpc"

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

	const styleCSS = `
* { box-sizing: border-box; }
html, body {
	padding: 0; margin: 0;
}

h1 {
	margin: 0;
}

body {
	font-family: Helvetica, Arial, sans-serif;
	background-color: whitesmoke;
}

#box {
	position: relative;
	margin: 5vh auto 0;
	width: 75vw;
	background: white;
	border: 1px solid #ddd;

	padding: 50px 20px;
	text-align: center;
}

@media screen and (max-width: 600px) {
	#box {
		width: 100vw;
		border-left: 0;
		border-right: 0;
	}
}
`

	const postSigninJS = `
(function() {
	"use strict";

	console.log("Beginning post-signin checks.");

	const fetchAndReturnWhenReady = (url) => new Promise((resolve, reject) => {
		const attemptFetch = () => {
			fetch(url)
			.then((res) => {
				if (!res.ok) throw new Error('Failed to fetch ' + url);
				return res.json();
			})
			.then((j) => {
				if (j.ok) {
					resolve();
				}
				throw new Error('Not ready yet.');
			})
			.catch((err) => {
				console.error(err);
				setTimeout(attemptFetch, 1000);
			});
		};
		attemptFetch();
	});

	Promise.all([
		fetchAndReturnWhenReady('https://v4-captive.house.as205479.net/isdone'),
		fetchAndReturnWhenReady('https://v6-captive.house.as205479.net/isdone'),
	]).then(() => {
		let nextURL = document.querySelector('meta[name="next-url"]').value;
		if (!nextURL) {
			nextURL = 'https://as205479.net';
		}
		window.location = nextURL;
	});

})();
`

	const indexRawTpl = `<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<title>Welcome to AS205479 Wifi</title>
	<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" />
	<link rel="stylesheet" type="text/css" href="/style.css">
</head>
<body>
	<div id="box">
		<h1>Welcome to AS205479 Wifi</h1>
		<p>Please log in with your Google account to continue:</p>
		<a href="/start"><img src="data:image/png;base64,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"></a>
	</div>
</body>
</html>
`
	indexTpl, err := template.New("index").Parse(indexRawTpl)
	if err != nil {
		log.Fatal(err)
	}

	const doneRawTpl = `<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<title>Welcome to AS205479 Wifi</title>
	<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" />
	<link rel="stylesheet" type="text/css" href="/style.css">
	<script src="/postsignin.js" async defer></script>
	<meta name="next-url" content="{{.Next}}">
</head>
<body>
	<div id="box">
		<h1>Welcome to AS205479 Wifi</h1>
		<h2>Please wait while you're logged in...</h2>
		<p>This may take about a minute, and only happens the first time you connect to this wifi network from this device.</p>
	</div>
</body>
</html>
`
	doneTpl, err := template.New("done").Parse(doneRawTpl)
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.Error(w, "page not found", http.StatusNotFound)
			return
		}

		d := struct {
			Next     string
			ClientID string
		}{
			Next:     r.URL.Query().Get("next"),
			ClientID: *flagClientID,
		}

		err := indexTpl.Execute(w, d)
		if err != nil {
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
	http.HandleFunc("/postsignin.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, postSigninJS)
	})
	http.HandleFunc("/style.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		fmt.Fprint(w, styleCSS)
	})
	http.HandleFunc("/isdone", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://captive.house.as205479.net")
		w.Header().Set("Access-Control-Allow-Methods", "GET")

		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		isBad := strings.HasPrefix(host, "2a07:1c44:3636:201:") || strings.HasPrefix(host, "172.27.201.")

		v := struct {
			OK bool `json:"ok"`
		}{!isBad}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	})
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
		if sentState != mac.String() {
			http.Error(w, "bad session state", http.StatusBadRequest)
			return
		}

		tok, err := conf.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "bad oauth token", http.StatusBadRequest)
			return
		}

		client := conf.Client(ctx, tok)
		resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
		if err != nil {
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
			http.Error(w, fmt.Sprintf("google userinfo API returned garbage: %v", err), http.StatusBadGateway)
			return
		}

		if !d.EmailVerified {
			http.Error(w, fmt.Sprintf("user %v does not have verified email", d.Email), http.StatusBadRequest)
			return
		}

		if err := authorizeMAC(ctx, mac, d.Email); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		next := r.URL.Query().Get("next")
		if next == "" {
			next = "https://as205479.net"
		}

		d2 := struct {
			Next string
		}{next}
		if err := doneTpl.Execute(w, d2); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	laddr := strings.Split(*flagListenAddr, ",")
	for _, n := range laddr[:len(laddr)-1] {
		go listen(n, tc)
	}
	listen(laddr[len(laddr)-1], tc)
}
