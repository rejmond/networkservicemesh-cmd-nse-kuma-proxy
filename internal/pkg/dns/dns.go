// Copyright (c) 2022 Xored Software Inc and others.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux
// +build linux

// Package dns provides dns server with rewrite modification
package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/miekg/dns"
)

// ProxyRewriteServer - DNS server with rewrite function
type ProxyRewriteServer struct {
	RewriteTO       net.IP
	ListenOn        string
	ResolveConfPath string
}

// ListenAndServe - run DNS server
func (p *ProxyRewriteServer) ListenAndServe(ctx context.Context) <-chan error {
	var networks = []string{"tcp", "udp"}
	var result = make(chan error, len(networks))
	var waitGroup sync.WaitGroup

	if p.RewriteTO == nil {
		result <- errors.New("RewriteTO is not set")
	}
	if p.ResolveConfPath == "" {
		p.ResolveConfPath = "/etc/resolv.conf"
	}

	for _, network := range networks {
		var server = &dns.Server{Addr: p.ListenOn, Net: network}
		server.Handler = p

		waitGroup.Add(1)

		go func() {
			defer waitGroup.Done()
			defer func() {
				_ = server.Shutdown()
			}()
			if err := server.ListenAndServe(); err != nil {
				result <- err
			}

			<-ctx.Done()
		}()
	}

	go func() {
		waitGroup.Wait()
		close(result)
	}()

	return result
}

// ServeDNS - serve DNS request
func (p *ProxyRewriteServer) ServeDNS(rw dns.ResponseWriter, m *dns.Msg) {
	config, err := dns.ClientConfigFromFile(p.ResolveConfPath)
	if err != nil {
		dns.HandleFailed(rw, m)
		return
	}
	var networks = []string{"tcp", "udp"}

	for _, network := range networks {
		var client = dns.Client{
			Net: network,
		}
		for _, addr := range config.Servers {
			var msg *dns.Msg
			if msg, _, err = client.Exchange(m, fmt.Sprintf("%v:%v", addr, config.Port)); err != nil {
				fmt.Println(err.Error())
				continue
			}
			for _, answer := range msg.Answer {
				p.rewriteIP(answer)
			}
			if err := rw.WriteMsg(msg); err == nil {
				return
			}
		}
	}

	dns.HandleFailed(rw, m)
}

func (p *ProxyRewriteServer) rewriteIP(rr dns.RR) {
	switch rr.Header().Rrtype {
	case dns.TypeAAAA:
		if p.RewriteTO.To16() != nil {
			rr.(*dns.AAAA).AAAA = p.RewriteTO.To16()
		}
	case dns.TypeA:
		if p.RewriteTO.To4() != nil {
			rr.(*dns.A).A = p.RewriteTO.To4()
		}
	}
}
