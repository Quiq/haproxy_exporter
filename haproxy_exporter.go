// Copyright 2018 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"crypto/tls"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"
	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	namespace = "haproxy" // For Prometheus metrics.

	// HAProxy 1.4
	// # pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,status,weight,act,bck,chkfail,chkdown,lastchg,downtime,qlimit,pid,iid,sid,throttle,lbtot,tracked,type,rate,rate_lim,rate_max,check_status,check_code,check_duration,hrsp_1xx,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,hrsp_other,hanafail,req_rate,req_rate_max,req_tot,cli_abrt,srv_abrt,
	// HAProxy 1.5
	// pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,status,weight,act,bck,chkfail,chkdown,lastchg,downtime,qlimit,pid,iid,sid,throttle,lbtot,tracked,type,rate,rate_lim,rate_max,check_status,check_code,check_duration,hrsp_1xx,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,hrsp_other,hanafail,req_rate,req_rate_max,req_tot,cli_abrt,srv_abrt,comp_in,comp_out,comp_byp,comp_rsp,lastsess,
	// HAProxy 1.5.19
	// pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,status,weight,act,bck,chkfail,chkdown,lastchg,downtime,qlimit,pid,iid,sid,throttle,lbtot,tracked,type,rate,rate_lim,rate_max,check_status,check_code,check_duration,hrsp_1xx,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,hrsp_other,hanafail,req_rate,req_rate_max,req_tot,cli_abrt,srv_abrt,comp_in,comp_out,comp_byp,comp_rsp,lastsess,last_chk,last_agt,qtime,ctime,rtime,ttime,
	// HAProxy 1.7
	// pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,status,weight,act,bck,chkfail,chkdown,lastchg,downtime,qlimit,pid,iid,sid,throttle,lbtot,tracked,type,rate,rate_lim,rate_max,check_status,check_code,check_duration,hrsp_1xx,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,hrsp_other,hanafail,req_rate,req_rate_max,req_tot,cli_abrt,srv_abrt,comp_in,comp_out,comp_byp,comp_rsp,lastsess,last_chk,last_agt,qtime,ctime,rtime,ttime,agent_status,agent_code,agent_duration,check_desc,agent_desc,check_rise,check_fall,check_health,agent_rise,agent_fall,agent_health,addr,cookie,mode,algo,conn_rate,conn_rate_max,conn_tot,intercepted,dcon,dses
	// HAProxy 2.3
	// # pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,status,weight,act,bck,chkfail,chkdown,lastchg,downtime,qlimit,pid,iid,sid,throttle,lbtot,tracked,type,rate,rate_lim,rate_max,check_status,check_code,check_duration,hrsp_1xx,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,hrsp_other,hanafail,req_rate,req_rate_max,req_tot,cli_abrt,srv_abrt,comp_in,comp_out,comp_byp,comp_rsp,lastsess,last_chk,last_agt,qtime,ctime,rtime,ttime,agent_status,agent_code,agent_duration,check_desc,agent_desc,check_rise,check_fall,check_health,agent_rise,agent_fall,agent_health,addr,cookie,mode,algo,conn_rate,conn_rate_max,conn_tot,intercepted,dcon,dses,wrew,connect,reuse,cache_lookups,cache_hits,srv_icur,src_ilim,qtime_max,ctime_max,rtime_max,ttime_max,eint,idle_conn_cur,safe_conn_cur,used_conn_cur,need_conn_est,uweight,-,h2_headers_rcvd,h2_data_rcvd,h2_settings_rcvd,h2_rst_stream_rcvd,h2_goaway_rcvd,h2_detected_conn_protocol_errors,h2_detected_strm_protocol_errors,h2_rst_stream_resp,h2_goaway_resp,h2_open_connections,h2_backend_open_streams,h2_total_connections,h2_backend_total_streams,
	minimumCsvFieldCount = 33

	pxnameField        = 0
	svnameField        = 1
	statusField        = 17
	typeField          = 32
	checkDurationField = 38
	qtimeMsField       = 58
	ctimeMsField       = 59
	rtimeMsField       = 60
	ttimeMsField       = 61

	excludedServerStates = ""
	showStatCmd          = "show stat\n"
	showInfoCmd          = "show info\n"
)

var (
	frontendLabelNames = []string{"frontend"}
	backendLabelNames  = []string{"backend"}
	serverLabelNames   = []string{"backend", "server"}
)

type metricInfo struct {
	Desc *prometheus.Desc
	Type prometheus.ValueType
}

func newFrontendMetric(metricName string, docString string, t prometheus.ValueType, constLabels prometheus.Labels) metricInfo {
	return metricInfo{
		Desc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "frontend", metricName),
			docString,
			frontendLabelNames,
			constLabels,
		),
		Type: t,
	}
}

func newBackendMetric(metricName string, docString string, t prometheus.ValueType, constLabels prometheus.Labels) metricInfo {
	return metricInfo{
		Desc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "backend", metricName),
			docString,
			backendLabelNames,
			constLabels,
		),
		Type: t,
	}
}

func newServerMetric(metricName string, docString string, t prometheus.ValueType, constLabels prometheus.Labels) metricInfo {
	return metricInfo{
		Desc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "server", metricName),
			docString,
			serverLabelNames,
			constLabels,
		),
		Type: t,
	}
}

type metrics map[int]metricInfo

func (m metrics) String() string {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	s := make([]string, len(keys))
	for i, k := range keys {
		s[i] = strconv.Itoa(k)
	}
	return strings.Join(s, ",")
}

var serverMetricsString = "2,3,4,5,6,7,8,9,13,14,15,16,17,18,21,24,30,33,35,38,39,40,41,42,43,44,49,50,58,59,60,61"

func addLabel(origin, add prometheus.Labels) prometheus.Labels {

	customLabel := prometheus.Labels{}
	for k, v := range origin {
		customLabel[k] = v
	}
	for k, v := range add {
		customLabel[k] = v
	}
	return customLabel
}

// Exporter collects HAProxy stats from the given URI and exports them using
// the prometheus metrics package.
type Exporter struct {
	URI       string
	mutex     sync.RWMutex
	fetchInfo func() (io.ReadCloser, error)
	fetchStat func() (io.ReadCloser, error)

	haproxyInfo                    *prometheus.Desc
	haproxyUp                      *prometheus.Desc
	up                             prometheus.Gauge
	totalScrapes, csvParseFailures prometheus.Counter
	frontendMetrics, backendMetrics, serverMetrics map[int]metricInfo
	excludedServerStates           map[string]struct{}
	logger                         log.Logger
}

// NewExporter returns an initialized Exporter.
func NewExporter(uri string, sslVerify bool, excludedServerStates string, timeout time.Duration, labels prometheus.Labels, logger log.Logger) (*Exporter, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	var fetchInfo func() (io.ReadCloser, error)
	var fetchStat func() (io.ReadCloser, error)
	switch u.Scheme {
	case "http", "https", "file":
		fetchStat = fetchHTTP(uri, sslVerify, timeout)
	case "unix":
		fetchInfo = fetchAddress("unix", u.Path, showInfoCmd, timeout)
		fetchStat = fetchAddress("unix", u.Path, showStatCmd, timeout)
	case "tcp":
		fetchStat = fetchAddress("tcp", u.Host, showStatCmd, timeout)
	default:
		return nil, fmt.Errorf("unsupported scheme: %q", u.Scheme)
	}
	if labels == nil {
		labels = prometheus.Labels{}
	}

	excludedServerStatesMap := map[string]struct{}{}
	for _, f := range strings.Split(excludedServerStates, ",") {
		excludedServerStatesMap[f] = struct{}{}
	}

	return &Exporter{
		URI:       uri,
		fetchInfo: fetchInfo,
		fetchStat: fetchStat,
		haproxyInfo: prometheus.NewDesc(prometheus.BuildFQName(namespace, "version", "info"), "HAProxy version info.", []string{"release_date", "version"}, labels),
		haproxyUp: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "up"), "Was the last scrape of HAProxy successful.", nil, labels),
		up: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   namespace,
			Name:        "up",
			Help:        "Was the last scrape of HAProxy successful.",
			ConstLabels: labels,
		}),
		totalScrapes: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "exporter_scrapes_total",
			Help:      "Current total HAProxy scrapes.",
			ConstLabels: labels,
		}),
		csvParseFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "exporter_csv_parse_failures_total",
			Help:      "Number of errors while parsing CSV.",
			ConstLabels: labels,
		}),
		serverMetrics: metrics{
			2:  newServerMetric("current_queue", "Current number of queued requests assigned to this server.", prometheus.GaugeValue, labels),
			3:  newServerMetric("max_queue", "Maximum observed number of queued requests assigned to this server.", prometheus.GaugeValue, labels),
			4:  newServerMetric("current_sessions", "Current number of active sessions.", prometheus.GaugeValue, labels),
			5:  newServerMetric("max_sessions", "Maximum observed number of active sessions.", prometheus.GaugeValue, labels),
			6:  newServerMetric("limit_sessions", "Configured session limit.", prometheus.GaugeValue, labels),
			7:  newServerMetric("sessions_total", "Total number of sessions.", prometheus.CounterValue, labels),
			8:  newServerMetric("bytes_in_total", "Current total of incoming bytes.", prometheus.CounterValue, labels),
			9:  newServerMetric("bytes_out_total", "Current total of outgoing bytes.", prometheus.CounterValue, labels),
			13: newServerMetric("connection_errors_total", "Total of connection errors.", prometheus.CounterValue, labels),
			14: newServerMetric("response_errors_total", "Total of response errors.", prometheus.CounterValue, labels),
			15: newServerMetric("retry_warnings_total", "Total of retry warnings.", prometheus.CounterValue, labels),
			16: newServerMetric("redispatch_warnings_total", "Total of redispatch warnings.", prometheus.CounterValue, labels),
			17: newServerMetric("up", "Current health status of the server (1 = UP, 0 = DOWN).", prometheus.GaugeValue, labels),
			18: newServerMetric("weight", "Current weight of the server.", prometheus.GaugeValue, labels),
			21: newServerMetric("check_failures_total", "Total number of failed health checks.", prometheus.CounterValue, labels),
			24: newServerMetric("downtime_seconds_total", "Total downtime in seconds.", prometheus.CounterValue, labels),
			30: newServerMetric("server_selected_total", "Total number of times a server was selected, either for new sessions, or when re-dispatching.", prometheus.CounterValue, labels),
			33: newServerMetric("current_session_rate", "Current number of sessions per second over last elapsed second.", prometheus.GaugeValue, labels),
			35: newServerMetric("max_session_rate", "Maximum observed number of sessions per second.", prometheus.GaugeValue, labels),
			38: newServerMetric("check_duration_seconds", "Previously run health check duration, in seconds", prometheus.GaugeValue, labels),
			39: newServerMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, addLabel(labels, prometheus.Labels{"code": "1xx"})),
			40: newServerMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, addLabel(labels, prometheus.Labels{"code": "2xx"})),
			41: newServerMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, addLabel(labels, prometheus.Labels{"code": "3xx"})),
			42: newServerMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, addLabel(labels, prometheus.Labels{"code": "4xx"})),
			43: newServerMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, addLabel(labels, prometheus.Labels{"code": "5xx"})),
			44: newServerMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, addLabel(labels, prometheus.Labels{"code": "other"})),
			49: newServerMetric("client_aborts_total", "Total number of data transfers aborted by the client.", prometheus.CounterValue, labels),
			50: newServerMetric("server_aborts_total", "Total number of data transfers aborted by the server.", prometheus.CounterValue, labels),
			58: newServerMetric("http_queue_time_average_seconds", "Avg. HTTP queue time for last 1024 successful connections.", prometheus.GaugeValue, labels),
			59: newServerMetric("http_connect_time_average_seconds", "Avg. HTTP connect time for last 1024 successful connections.", prometheus.GaugeValue, labels),
			60: newServerMetric("http_response_time_average_seconds", "Avg. HTTP response time for last 1024 successful connections.", prometheus.GaugeValue, labels),
			61: newServerMetric("http_total_time_average_seconds", "Avg. HTTP total time for last 1024 successful connections.", prometheus.GaugeValue, labels),
		},

		frontendMetrics: metrics{
			4:  newFrontendMetric("current_sessions", "Current number of active sessions.", prometheus.GaugeValue, labels),
			5:  newFrontendMetric("max_sessions", "Maximum observed number of active sessions.", prometheus.GaugeValue, labels),
			6:  newFrontendMetric("limit_sessions", "Configured session limit.", prometheus.GaugeValue, labels),
			7:  newFrontendMetric("sessions_total", "Total number of sessions.", prometheus.CounterValue, labels),
			8:  newFrontendMetric("bytes_in_total", "Current total of incoming bytes.", prometheus.CounterValue, labels),
			9:  newFrontendMetric("bytes_out_total", "Current total of outgoing bytes.", prometheus.CounterValue, labels),
			10: newFrontendMetric("requests_denied_total", "Total of requests denied for security.", prometheus.CounterValue, labels),
			12: newFrontendMetric("request_errors_total", "Total of request errors.", prometheus.CounterValue, labels),
			33: newFrontendMetric("current_session_rate", "Current number of sessions per second over last elapsed second.", prometheus.GaugeValue, labels),
			34: newFrontendMetric("limit_session_rate", "Configured limit on new sessions per second.", prometheus.GaugeValue, labels),
			35: newFrontendMetric("max_session_rate", "Maximum observed number of sessions per second.", prometheus.GaugeValue, labels),
			39: newFrontendMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, addLabel(labels, prometheus.Labels{"code": "1xx"})),
			40: newFrontendMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, addLabel(labels, prometheus.Labels{"code": "2xx"})),
			41: newFrontendMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, addLabel(labels, prometheus.Labels{"code": "3xx"})),
			42: newFrontendMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, addLabel(labels, prometheus.Labels{"code": "4xx"})),
			43: newFrontendMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, addLabel(labels, prometheus.Labels{"code": "5xx"})),
			44: newFrontendMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, addLabel(labels, prometheus.Labels{"code": "other"})),
			48: newFrontendMetric("http_requests_total", "Total HTTP requests.", prometheus.CounterValue, labels),
			51: newFrontendMetric("compressor_bytes_in_total", "Number of HTTP response bytes fed to the compressor", prometheus.CounterValue, labels),
			52: newFrontendMetric("compressor_bytes_out_total", "Number of HTTP response bytes emitted by the compressor", prometheus.CounterValue, labels),
			53: newFrontendMetric("compressor_bytes_bypassed_total", "Number of bytes that bypassed the HTTP compressor", prometheus.CounterValue, labels),
			54: newFrontendMetric("http_responses_compressed_total", "Number of HTTP responses that were compressed", prometheus.CounterValue, labels),
			79: newFrontendMetric("connections_total", "Total number of connections", prometheus.CounterValue, labels),
		},
		backendMetrics: metrics{
			2:  newBackendMetric("current_queue", "Current number of queued requests not assigned to any server.", prometheus.GaugeValue, labels),
			3:  newBackendMetric("max_queue", "Maximum observed number of queued requests not assigned to any server.", prometheus.GaugeValue, labels),
			4:  newBackendMetric("current_sessions", "Current number of active sessions.", prometheus.GaugeValue, labels),
			5:  newBackendMetric("max_sessions", "Maximum observed number of active sessions.", prometheus.GaugeValue, labels),
			6:  newBackendMetric("limit_sessions", "Configured session limit.", prometheus.GaugeValue, labels),
			7:  newBackendMetric("sessions_total", "Total number of sessions.", prometheus.CounterValue, labels),
			8:  newBackendMetric("bytes_in_total", "Current total of incoming bytes.", prometheus.CounterValue, labels),
			9:  newBackendMetric("bytes_out_total", "Current total of outgoing bytes.", prometheus.CounterValue, labels),
			13: newBackendMetric("connection_errors_total", "Total of connection errors.", prometheus.CounterValue, labels),
			14: newBackendMetric("response_errors_total", "Total of response errors.", prometheus.CounterValue, labels),
			15: newBackendMetric("retry_warnings_total", "Total of retry warnings.", prometheus.CounterValue, labels),
			16: newBackendMetric("redispatch_warnings_total", "Total of redispatch warnings.", prometheus.CounterValue, labels),
			17: newBackendMetric("up", "Current health status of the backend (1 = UP, 0 = DOWN).", prometheus.GaugeValue, labels),
			18: newBackendMetric("weight", "Total weight of the servers in the backend.", prometheus.GaugeValue, labels),
			19: newBackendMetric("current_server", "Current number of active servers", prometheus.GaugeValue, labels),
			30: newBackendMetric("server_selected_total", "Total number of times a server was selected, either for new sessions, or when re-dispatching.", prometheus.CounterValue, labels),
			33: newBackendMetric("current_session_rate", "Current number of sessions per second over last elapsed second.", prometheus.GaugeValue, labels),
			35: newBackendMetric("max_session_rate", "Maximum number of sessions per second.", prometheus.GaugeValue, labels),
			39: newBackendMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, addLabel(labels, prometheus.Labels{"code": "1xx"})),
			40: newBackendMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, addLabel(labels, prometheus.Labels{"code": "2xx"})),
			41: newBackendMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, addLabel(labels, prometheus.Labels{"code": "3xx"})),
			42: newBackendMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, addLabel(labels, prometheus.Labels{"code": "4xx"})),
			43: newBackendMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, addLabel(labels, prometheus.Labels{"code": "5xx"})),
			44: newBackendMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, addLabel(labels, prometheus.Labels{"code": "other"})),
			49: newBackendMetric("client_aborts_total", "Total number of data transfers aborted by the client.", prometheus.CounterValue, labels),
			50: newBackendMetric("server_aborts_total", "Total number of data transfers aborted by the server.", prometheus.CounterValue, labels),
			51: newBackendMetric("compressor_bytes_in_total", "Number of HTTP response bytes fed to the compressor", prometheus.CounterValue, labels),
			52: newBackendMetric("compressor_bytes_out_total", "Number of HTTP response bytes emitted by the compressor", prometheus.CounterValue, labels),
			53: newBackendMetric("compressor_bytes_bypassed_total", "Number of bytes that bypassed the HTTP compressor", prometheus.CounterValue, labels),
			54: newBackendMetric("http_responses_compressed_total", "Number of HTTP responses that were compressed", prometheus.CounterValue, labels),
			58: newBackendMetric("http_queue_time_average_seconds", "Avg. HTTP queue time for last 1024 successful connections.", prometheus.GaugeValue, labels),
			59: newBackendMetric("http_connect_time_average_seconds", "Avg. HTTP connect time for last 1024 successful connections.", prometheus.GaugeValue, labels),
			60: newBackendMetric("http_response_time_average_seconds", "Avg. HTTP response time for last 1024 successful connections.", prometheus.GaugeValue, labels),
			61: newBackendMetric("http_total_time_average_seconds", "Avg. HTTP total time for last 1024 successful connections.", prometheus.GaugeValue, labels),
		},
		excludedServerStates: excludedServerStatesMap,
		logger:               logger,
	}, nil
}

// Describe describes all the metrics ever exported by the HAProxy exporter. It
// implements prometheus.Collector.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	for _, m := range e.frontendMetrics {
		ch <- m.Desc
	}
	for _, m := range e.backendMetrics {
		ch <- m.Desc
	}
	for _, m := range e.serverMetrics {
		ch <- m.Desc
	}
	ch <- e.up.Desc()
	ch <- e.haproxyInfo
	ch <- e.haproxyUp
	ch <- e.totalScrapes.Desc()
	ch <- e.csvParseFailures.Desc()
}

// Collect fetches the stats from configured HAProxy location and delivers them
// as Prometheus metrics. It implements prometheus.Collector.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	e.mutex.Lock() // To protect metrics from concurrent collects.
	defer e.mutex.Unlock()

	up := e.scrape(ch)

	ch <- prometheus.MustNewConstMetric(e.up.Desc(), prometheus.GaugeValue, up)
	ch <- e.totalScrapes
	ch <- e.csvParseFailures
}

func fetchHTTP(uri string, sslVerify bool, timeout time.Duration) func() (io.ReadCloser, error) {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: !sslVerify}}
	client := http.Client{
		Timeout:   timeout,
		Transport: tr,
	}

	return func() (io.ReadCloser, error) {
		resp, err := client.Get(uri)
		if err != nil {
			return nil, err
		}
		if !(resp.StatusCode >= 200 && resp.StatusCode < 300) {
			resp.Body.Close()
			return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
		}
		return resp.Body, nil
	}
}

func fetchAddress(network, address string, cmd string, timeout time.Duration) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) {
		f, err := net.DialTimeout(network, address, timeout)
		if err != nil {
			return nil, err
		}
		if err := f.SetDeadline(time.Now().Add(timeout)); err != nil {
			f.Close()
			return nil, err
		}
		n, err := io.WriteString(f, cmd)
		if err != nil {
			f.Close()
			return nil, err
		}
		if n != len(cmd) {
			f.Close()
			return nil, errors.New("write error")
		}
		return f, nil
	}
}

func (e *Exporter) scrape(ch chan<- prometheus.Metric) (up float64) {
	e.totalScrapes.Inc()
	var err error

	if e.fetchInfo != nil {
		infoReader, err := e.fetchInfo()
		if err != nil {
			level.Error(e.logger).Log("msg", "Can't scrape HAProxy", "err", err)
			return 0
		}
		defer infoReader.Close()

		info, err := e.parseInfo(infoReader)
		if err != nil {
			level.Debug(e.logger).Log("msg", "Failed parsing show info", "err", err)
		} else {
			ch <- prometheus.MustNewConstMetric(e.haproxyInfo, prometheus.GaugeValue, 1, info.ReleaseDate, info.Version)
		}
	}

	body, err := e.fetchStat()
	if err != nil {
		level.Error(e.logger).Log("msg", "Can't scrape HAProxy", "err", err)
		return 0
	}
	defer body.Close()

	reader := csv.NewReader(body)
	reader.TrailingComma = true
	reader.Comment = '#'

loop:
	for {
		row, err := reader.Read()
		switch err {
		case nil:
		case io.EOF:
			break loop
		default:
			if _, ok := err.(*csv.ParseError); ok {
				level.Error(e.logger).Log("msg", "Can't read CSV", "err", err)
				e.csvParseFailures.Inc()
				continue loop
			}
			level.Error(e.logger).Log("msg", "Unexpected error while reading CSV", "err", err)
			return 0
		}
		e.parseRow(row, ch)
	}
	return 1
}

type versionInfo struct {
	ReleaseDate string
	Version     string
}

func (e *Exporter) parseInfo(i io.Reader) (versionInfo, error) {
	var version, releaseDate string
	s := bufio.NewScanner(i)
	for s.Scan() {
		line := s.Text()
		if !strings.Contains(line, ":") {
			continue
		}

		field := strings.SplitN(line, ": ", 2)
		switch field[0] {
		case "Release_date":
			releaseDate = field[1]
		case "Version":
			version = field[1]
		}
	}
	return versionInfo{ReleaseDate: releaseDate, Version: version}, s.Err()
}

func (e *Exporter) parseRow(csvRow []string, ch chan<- prometheus.Metric) {
	if len(csvRow) < minimumCsvFieldCount {
		level.Error(e.logger).Log("msg", "Parser received unexpected number of CSV fields", "min", minimumCsvFieldCount, "received", len(csvRow))
		e.csvParseFailures.Inc()
		return
	}

	pxname, svname, status, typ := csvRow[pxnameField], csvRow[svnameField], csvRow[statusField], csvRow[typeField]

	const (
		frontend = "0"
		backend  = "1"
		server   = "2"
	)

	switch typ {
	case frontend:
		e.exportCsvFields(e.frontendMetrics, csvRow, ch, pxname)
	case backend:
		e.exportCsvFields(e.backendMetrics, csvRow, ch, pxname)
	case server:

		if _, ok := e.excludedServerStates[status]; !ok {
			e.exportCsvFields(e.serverMetrics, csvRow, ch, pxname, svname)
		}
	}
}

func parseStatusField(value string) int64 {
	switch value {
	case "UP", "UP 1/3", "UP 2/3", "OPEN", "no check", "DRAIN":
		return 1
	case "DOWN", "DOWN 1/2", "NOLB", "MAINT", "MAINT(via)", "MAINT(resolution)":
		return 0
	default:
		return 0
	}
}

func (e *Exporter) exportCsvFields(metrics map[int]metricInfo, csvRow []string, ch chan<- prometheus.Metric, labels ...string) {
	for fieldIdx, metric := range metrics {
		if fieldIdx > len(csvRow)-1 {
			// We can't break here because we are not looping over the fields in sorted order.
			continue
		}
		valueStr := csvRow[fieldIdx]
		if valueStr == "" {
			continue
		}

		var err error = nil
		var value float64
		var valueInt int64

		switch fieldIdx {
		case statusField:
			valueInt = parseStatusField(valueStr)
			value = float64(valueInt)
		case checkDurationField, qtimeMsField, ctimeMsField, rtimeMsField, ttimeMsField:
			value, err = strconv.ParseFloat(valueStr, 64)
			value /= 1000
		default:
			valueInt, err = strconv.ParseInt(valueStr, 10, 64)
			value = float64(valueInt)
		}
		if err != nil {
			level.Error(e.logger).Log("msg", "Can't parse CSV field value", "value", valueStr, "err", err)
			e.csvParseFailures.Inc()
			continue
		}
		ch <- prometheus.MustNewConstMetric(metric.Desc, metric.Type, value, labels...)
	}
}

// filterServerMetrics returns the set of server metrics specified by the comma
// separated filter.
func (e *Exporter) filterServerMetrics(filter string) error {
	metrics := map[int]metricInfo{}
	if len(filter) == 0 {
		e.serverMetrics = metrics
		return nil
	}

	selected := map[int]struct{}{}
	for _, f := range strings.Split(filter, ",") {
		field, err := strconv.Atoi(f)
		if err != nil {
			return fmt.Errorf("invalid server metric field number: %v", f)
		}
		selected[field] = struct{}{}
	}
	level.Debug(e.logger).Log(e.serverMetrics)
	for field, metric := range e.serverMetrics {
		if _, ok := selected[field]; ok {
			metrics[field] = metric
		}
	}

	e.serverMetrics = metrics
	return nil
}

func main() {
	const pidFileHelpText = `Path to HAProxy pid file.

	If provided, the standard process metrics get exported for the HAProxy
	process, prefixed with 'haproxy_process_...'. The haproxy_process exporter
	needs to have read access to files owned by the HAProxy process. Depends on
	the availability of /proc.

	https://prometheus.io/docs/instrumenting/writing_clientlibs/#process-metrics.`

	var (
		webConfig                  = webflag.AddFlags(kingpin.CommandLine)
		listenAddress              = kingpin.Flag("web.listen-address", "Address to listen on for web interface and telemetry.").Default(":9101").String()
		metricsPath                = kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
		haProxyScrapeURI           = kingpin.Flag("haproxy.scrape-uri", "URI on which to scrape HAProxy.").Default("http://localhost/;csv").String()
		haProxySSLVerify           = kingpin.Flag("haproxy.ssl-verify", "Flag that enables SSL certificate verification for the scrape URI").Default("true").Bool()
		haProxyServerMetricFields  = kingpin.Flag("haproxy.server-metric-fields", "Comma-separated list of exported server metrics. See http://cbonte.github.io/haproxy-dconv/configuration-1.5.html#9.1").Default(serverMetricsString).String()
		haProxyServerExcludeStates = kingpin.Flag("haproxy.server-exclude-states", "Comma-separated list of exported server states to exclude. See https://cbonte.github.io/haproxy-dconv/1.8/management.html#9.1, field 17 statuus").Default(excludedServerStates).String()
		haProxyTimeout             = kingpin.Flag("haproxy.timeout", "Timeout for trying to get stats from HAProxy.").Default("5s").Duration()
		haProxyPidFile             = kingpin.Flag("haproxy.pid-file", pidFileHelpText).Default("").String()
		haProxyScrapeURIs          = kingpin.Flag("haproxy.scrape-uris", "URIs on which to scrape HAProxy.").Default("").String()
	)

	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("haproxy_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promlog.New(promlogConfig)

	level.Info(logger).Log("Starting haproxy_exporter", version.Info())
	level.Info(logger).Log("Build context", version.BuildContext())

	if *haProxyScrapeURIs != "" {
		for i, uri := range strings.Split(*haProxyScrapeURIs, ",") {

			level.Info(logger).Log("Added socket uri: ", uri)
			exporter, err := NewExporter(uri, *haProxySSLVerify, *haProxyServerExcludeStates, *haProxyTimeout, prometheus.Labels{"socket": uri}, logger)
			if err != nil {
				level.Error(logger).Log(err)
				os.Exit(1)
			}
			err = exporter.filterServerMetrics(*haProxyServerMetricFields)
			if err != nil {
				level.Error(logger).Log(err)
				os.Exit(1)
			}
			prometheus.MustRegister(exporter)
			prometheus.MustRegister(version.NewCollector(fmt.Sprintf("haproxy_exporter_%d", i)))

		}
	} else {
		exporter, err := NewExporter(*haProxyScrapeURI, *haProxySSLVerify, *haProxyServerExcludeStates, *haProxyTimeout, nil, logger)
		if err != nil {
			level.Error(logger).Log(err)
			os.Exit(1)
		}
		err = exporter.filterServerMetrics(*haProxyServerMetricFields)
		if err != nil {
			level.Error(logger).Log(err)
			os.Exit(1)
		}
		prometheus.MustRegister(exporter)
		prometheus.MustRegister(version.NewCollector("haproxy_exporter"))
	}

	if *haProxyPidFile != "" {
		procExporter := prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{
			PidFn: func() (int, error) {
				content, err := ioutil.ReadFile(*haProxyPidFile)
				if err != nil {
					return 0, fmt.Errorf("can't read pid file: %s", err)
				}
				value, err := strconv.Atoi(strings.TrimSpace(string(content)))
				if err != nil {
					return 0, fmt.Errorf("can't parse pid file: %s", err)
				}
				return value, nil
			},
			Namespace: namespace,
		})
		prometheus.MustRegister(procExporter)
	}

	level.Info(logger).Log("msg", "Listening on address", "address", *listenAddress)
	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>Haproxy Exporter</title></head>
             <body>
             <h1>Haproxy Exporter</h1>
             <p><a href='` + *metricsPath + `'>Metrics</a></p>
             </body>
             </html>`))
	})
	srv := &http.Server{Addr: *listenAddress}
	if err := web.ListenAndServe(srv, *webConfig, logger); err != nil {
		level.Error(logger).Log("msg", "Error starting HTTP server", "err", err)
		os.Exit(1)
	}
}
