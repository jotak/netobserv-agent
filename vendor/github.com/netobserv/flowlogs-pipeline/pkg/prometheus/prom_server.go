/*
 * Copyright (C) 2023 IBM, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package prometheus

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"

	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	prom "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

var plog = logrus.WithField("component", "prometheus")

// StartServerAsync listens for prometheus resource usage requests
func StartServerAsync(settings *config.MetricsSettings) *http.Server {
	// create prometheus server for operational metrics
	// if value of address is empty, then by default it will take 0.0.0.0
	port := settings.Port
	if port == 0 {
		port = 9090
	}
	addr := fmt.Sprintf("%s:%v", settings.Address, port)
	plog.Infof("StartServerAsync: addr = %s", addr)

	// set up private prometheus registry
	if settings.SuppressGoMetrics {
		reg := prom.NewRegistry()
		prom.DefaultRegisterer = reg
		prom.DefaultGatherer = reg
	}

	httpServer := http.Server{
		Addr: addr,
		// TLS clients must use TLS 1.2 or higher
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	// The Handler function provides a default handler to expose metrics
	// via an HTTP server. "/metrics" is the usual endpoint for that.
	http.Handle("/metrics", promhttp.Handler())

	go func() {
		var err error
		if settings.TLS != nil {
			err = httpServer.ListenAndServeTLS(settings.TLS.CertPath, settings.TLS.KeyPath)
		} else {
			err = httpServer.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			logrus.Errorf("error in http.ListenAndServe: %v", err)
			if !settings.NoPanic {
				os.Exit(1)
			}
		}
	}()

	return &httpServer
}
