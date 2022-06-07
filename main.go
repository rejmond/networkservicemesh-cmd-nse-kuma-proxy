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

package main

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	nested "github.com/antonfisher/nested-logrus-formatter"
	"github.com/edwarnicke/grpcfd"
	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	kernelmech "github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/kernel"
	registryapi "github.com/networkservicemesh/api/pkg/api/registry"
	"github.com/networkservicemesh/cmd-nse-kuma-proxy/internal/pkg/dns"
	"github.com/networkservicemesh/sdk-kernel/pkg/kernel/networkservice/setiptables4nattemplate"
	"github.com/networkservicemesh/sdk-kernel/pkg/kernel/networkservice/setroutelocalnet"
	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/endpoint"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/authorize"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/kernel"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/recvfd"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/sendfd"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/onidle"
	"github.com/networkservicemesh/sdk/pkg/networkservice/connectioncontext/dnscontext"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/chain"
	"github.com/networkservicemesh/sdk/pkg/networkservice/ipam/point2pointipam"
	registryclient "github.com/networkservicemesh/sdk/pkg/registry/chains/client"
	registrysendfd "github.com/networkservicemesh/sdk/pkg/registry/common/sendfd"
	"github.com/networkservicemesh/sdk/pkg/tools/clientinfo"
	"github.com/networkservicemesh/sdk/pkg/tools/debug"
	dnstools "github.com/networkservicemesh/sdk/pkg/tools/dnscontext"
	"github.com/networkservicemesh/sdk/pkg/tools/grpcutils"
	"github.com/networkservicemesh/sdk/pkg/tools/log"
	"github.com/networkservicemesh/sdk/pkg/tools/log/logruslogger"
	"github.com/networkservicemesh/sdk/pkg/tools/opentelemetry"
	"github.com/networkservicemesh/sdk/pkg/tools/spiffejwt"
	"github.com/networkservicemesh/sdk/pkg/tools/tracing"
)

// Config holds configuration parameters from environment variables
type Config struct {
	Name                  string            `default:"istio-proxy-server" desc:"Name of Istio Proxy Server"`
	BaseDir               string            `default:"./" desc:"base directory" split_words:"true"`
	ConnectTo             url.URL           `default:"unix:///var/lib/networkservicemesh/nsm.io.sock" desc:"url to connect to" split_words:"true"`
	MaxTokenLifetime      time.Duration     `default:"10m" desc:"maximum lifetime of tokens" split_words:"true"`
	ServiceNames          []string          `default:"istio-proxy-responder" desc:"Name of provided services" split_words:"true"`
	Labels                map[string]string `default:"" desc:"Endpoint labels"`
	DNSConfigs            dnstools.Decoder  `default:"[]" desc:"DNSConfigs represents array of DNSConfig in json format. See at model definition: https://github.com/networkservicemesh/api/blob/main/pkg/api/networkservice/connectioncontext.pb.go#L426-L435" split_words:"true"`
	CidrPrefix            []string          `default:"169.254.0.0/16" desc:"List of CIDR Prefix to assign IPv4 and IPv6 addresses from" split_words:"true"`
	IdleTimeout           time.Duration     `default:"0" desc:"timeout for automatic shutdown when there were no requests for specified time. Set 0 to disable auto-shutdown." split_words:"true"`
	LogLevel              string            `default:"INFO" desc:"Log level" split_words:"true"`
	OpenTelemetryEndpoint string            `default:"otel-collector.observability.svc.cluster.local:4317" desc:"OpenTelemetry Collector Endpoint"`
}

// Process prints and processes env to config
func (c *Config) Process() error {
	if err := envconfig.Usage("nsm", c); err != nil {
		return errors.Wrap(err, "cannot show usage of envconfig nse")
	}
	if err := envconfig.Process("nsm", c); err != nil {
		return errors.Wrap(err, "cannot process envconfig nse")
	}
	return nil
}

func main() {
	// ********************************************************************************
	// setup context to catch signals
	// ********************************************************************************
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		// More Linux signals here
		syscall.SIGHUP,
		syscall.SIGTERM,
		syscall.SIGQUIT,
	)
	defer cancel()

	// ********************************************************************************
	// setup logging
	// ********************************************************************************
	log.EnableTracing(true)
	logrus.SetFormatter(&nested.Formatter{})
	ctx = log.WithLog(ctx, logruslogger.New(ctx, map[string]interface{}{"cmd": os.Args[0]}))

	if err := debug.Self(); err != nil {
		log.FromContext(ctx).Infof("%s", err)
	}

	// enumerating phases
	log.FromContext(ctx).Infof("there are 6 phases which will be executed followed by a success message:")
	log.FromContext(ctx).Infof("the phases include:")
	log.FromContext(ctx).Infof("1: get config from environment")
	log.FromContext(ctx).Infof("2: retrieve spiffe svid")
	log.FromContext(ctx).Infof("3: create server ipam")
	log.FromContext(ctx).Infof("4: create server nse")
	log.FromContext(ctx).Infof("5: create grpc and mount nse")
	log.FromContext(ctx).Infof("6: register nse with nsm")
	log.FromContext(ctx).Infof("7: run DNS server")
	log.FromContext(ctx).Infof("8: run proxy server")
	log.FromContext(ctx).Infof("a final success message with start time duration")

	starttime := time.Now()

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 1: get config from environment")
	// ********************************************************************************
	config := new(Config)
	if err := config.Process(); err != nil {
		logrus.Fatal(err.Error())
	}

	// TODO Fix for multiple clients
	if len(config.CidrPrefix) != 1 {
		logrus.Fatal("Only one CIDR prefix expected")
	}
	ip, _, err := net.ParseCIDR(config.CidrPrefix[0])
	if err != nil {
		logrus.Fatalf("parsing CIDR error: %s", err.Error())
	}
	if ip.To4() == nil {
		logrus.Fatal("expected CIDR ipv4")
	}

	clientinfo.AddClientInfo(ctx, config.Labels)

	l, err := logrus.ParseLevel(config.LogLevel)
	if err != nil {
		logrus.Fatalf("invalid log level %s", config.LogLevel)
	}
	logrus.SetLevel(l)

	log.FromContext(ctx).Infof("Config: %#v", config)

	// ********************************************************************************
	// Configure Open Telemetry
	// ********************************************************************************
	if opentelemetry.IsEnabled() {
		collectorAddress := config.OpenTelemetryEndpoint
		spanExporter := opentelemetry.InitSpanExporter(ctx, collectorAddress)
		metricExporter := opentelemetry.InitMetricExporter(ctx, collectorAddress)
		o := opentelemetry.Init(ctx, spanExporter, metricExporter, config.Name)
		defer func() {
			if err = o.Close(); err != nil {
				log.FromContext(ctx).Error(err.Error())
			}
		}()
	}

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 2: retrieving svid, check spire agent logs if this is the last line you see")
	// ********************************************************************************
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		logrus.Fatalf("error getting x509 source: %+v", err)
	}
	svid, err := source.GetX509SVID()
	if err != nil {
		logrus.Fatalf("error getting x509 svid: %+v", err)
	}
	log.FromContext(ctx).Infof("SVID: %q", svid.ID)

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 3: creating server ipam")
	// ********************************************************************************
	ipamChain := getIPAMChain(ctx, config.CidrPrefix)

	log.FromContext(ctx).Infof("network prefixes parsed successfully")

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 4: create network service endpoint")
	// ********************************************************************************
	setRulesServer := getSetIPTablesRulesServerChainElement()

	config.DNSConfigs = append(config.DNSConfigs, &networkservice.DNSConfig{
		DnsServerIps: []string{ip.String()},
	})

	responderEndpoint := endpoint.NewServer(ctx,
		spiffejwt.TokenGeneratorFunc(source, config.MaxTokenLifetime),
		endpoint.WithName(config.Name),
		endpoint.WithAuthorizeServer(authorize.NewServer()),
		endpoint.WithAdditionalFunctionality(
			onidle.NewServer(ctx, cancel, config.IdleTimeout),
			ipamChain,
			recvfd.NewServer(),
			mechanisms.NewServer(map[string]networkservice.NetworkServiceServer{
				kernelmech.MECHANISM: kernel.NewServer(),
			}),
			dnscontext.NewServer(config.DNSConfigs...),
			setroutelocalnet.NewServer(),
			setRulesServer,
			sendfd.NewServer(),
		),
	)
	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 5: create grpc server and register icmp-server")
	// ********************************************************************************
	options := append(
		tracing.WithTracing(),
		grpc.Creds(
			grpcfd.TransportCredentials(
				credentials.NewTLS(
					tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeAny()),
				),
			),
		),
	)
	server := grpc.NewServer(options...)
	responderEndpoint.Register(server)
	tmpDir, err := ioutil.TempDir("", config.Name)
	if err != nil {
		logrus.Fatalf("error creating tmpDir %+v", err)
	}
	defer func(tmpDir string) { _ = os.Remove(tmpDir) }(tmpDir)
	listenOn := &(url.URL{Scheme: "unix", Path: filepath.Join(tmpDir, "listen.on")})
	srvErrCh := grpcutils.ListenAndServe(ctx, listenOn, server)
	exitOnErr(ctx, cancel, srvErrCh)
	log.FromContext(ctx).Infof("grpc server started")

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 6: register nse with nsm")
	// ********************************************************************************
	clientOptions := append(
		tracing.WithTracingDial(),
		grpc.WithBlock(),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
		grpc.WithTransportCredentials(
			grpcfd.TransportCredentials(
				credentials.NewTLS(
					tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny()),
				),
			),
		),
	)

	nseRegistryClient := registryclient.NewNetworkServiceEndpointRegistryClient(
		ctx,
		registryclient.WithClientURL(&config.ConnectTo),
		registryclient.WithDialOptions(clientOptions...),
		registryclient.WithNSEAdditionalFunctionality(
			registrysendfd.NewNetworkServiceEndpointRegistryClient(),
		),
	)
	nse := getNseEndpoint(config, listenOn)
	nse, err = nseRegistryClient.Register(ctx, nse)
	logrus.Infof("nse: %+v", nse)

	if err != nil {
		log.FromContext(ctx).Fatalf("unable to register nse %+v", err)
	}

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 7: run DNS server")
	// ********************************************************************************
	dnsServer := &dns.ProxyRewriteServer{
		RewriteTO: ip,
		ListenOn:  ":53",
	}

	var dnsServerErrCh = dnsServer.ListenAndServe(ctx)

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 8: run proxy server")
	// ********************************************************************************
	httpClient := &http.Client{}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "try to make a clone request to %s %s\n", r.Proto, r.Host)
		req, err := http.NewRequest(r.Method, fmt.Sprintf("http://%s", r.Host), r.Body)
		if r.Header != nil {
			req.Header = r.Header.Clone()
		}
		if r.Trailer != nil {
			req.Trailer = r.Trailer.Clone()
		}
		// TODO Make complex clone request
		//req := r.Clone(ctx)

		resp, err := httpClient.Do(req)
		if err != nil {
			fmt.Fprintf(w, "error at reqest %v", err.Error())
			return
		}

		body, err := io.ReadAll(resp.Body)

		if err != nil {
			fmt.Fprintf(w, "error at reading %v", err.Error())
			return
		}
		err = resp.Body.Close()

		if err != nil {
			fmt.Fprintf(w, "error at closing %v", err.Error())
			return
		}

		fmt.Fprintf(w, "result: %s\n", string(body))
		//w.Write(body)
	})
	err = http.ListenAndServe(":8080", nil)

	if err != nil {
		log.FromContext(ctx).Fatalf("unable to start http proxy server %+v", err)
	}

	// ********************************************************************************
	log.FromContext(ctx).Infof("startup completed in %v", time.Since(starttime))
	// ********************************************************************************

	// wait for server to exit
	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
			return
		case err, ok := <-dnsServerErrCh:
			if err != nil {
				log.FromContext(ctx).Errorf("ProxyRewriteServer: unexpected error: %v", err.Error())
			}
			if !ok {
				return
			}
		}
	}
}

func getNseEndpoint(config *Config, listenOn fmt.Stringer) *registryapi.NetworkServiceEndpoint {
	nse := &registryapi.NetworkServiceEndpoint{
		Name:                 config.Name,
		NetworkServiceNames:  config.ServiceNames,
		NetworkServiceLabels: make(map[string]*registryapi.NetworkServiceLabels),
		Url:                  listenOn.String(),
	}
	for _, serviceName := range config.ServiceNames {
		nse.NetworkServiceLabels[serviceName] = &registryapi.NetworkServiceLabels{Labels: config.Labels}
	}
	return nse
}

func getSetIPTablesRulesServerChainElement() networkservice.NetworkServiceServer {
	defaultRules := []string{
		"-N NSM_PREROUTE",
		"-A NSM_PREROUTE -p tcp -j REDIRECT --to-port 8080",
		//"-A NSM_PREROUTE -j MESH_REDIRECT",
		"-I PREROUTING 1 -p tcp -i {{ .NsmInterfaceName }} -j NSM_PREROUTE",
		//"-N NSM_OUTPUT",
		//"-A NSM_OUTPUT -j DNAT --to-destination {{ index .NsmSrcIPs 0 }}",
		//"-A OUTPUT -p tcp -s 127.0.0.6 -j NSM_OUTPUT",
		//"-N NSM_POSTROUTING",
		//"-A NSM_POSTROUTING -j SNAT --to-source {{ index .NsmDstIPs 0 }}",
		//"-A POSTROUTING -p tcp -o {{ .NsmInterfaceName }} -j NSM_POSTROUTING",
	}

	return setiptables4nattemplate.NewServer(defaultRules)
}

func exitOnErr(ctx context.Context, cancel context.CancelFunc, errCh <-chan error) {
	// If we already have an error, log it and exit
	select {
	case err := <-errCh:
		log.FromContext(ctx).Fatal(err)
	default:
	}
	// Otherwise wait for an error in the background to log and cancel
	go func(ctx context.Context, errCh <-chan error) {
		err := <-errCh
		log.FromContext(ctx).Error(err)
		cancel()
	}(ctx, errCh)
}

func getIPAMChain(ctx context.Context, cIDRs []string) networkservice.NetworkServiceServer {
	var ipamchain []networkservice.NetworkServiceServer
	for _, cidr := range cIDRs {
		var parseErr error
		_, ipNet, parseErr := net.ParseCIDR(strings.TrimSpace(cidr))
		if parseErr != nil {
			log.FromContext(ctx).Fatalf("Could not parse CIDR %s; %+v", cidr, parseErr)
		}
		ipamchain = append(ipamchain, point2pointipam.NewServer(ipNet))
	}
	return chain.NewNetworkServiceServer(ipamchain...)
}
