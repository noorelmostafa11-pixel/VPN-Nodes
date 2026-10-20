// node_delay is owned by VPN-Nodes. Build this explicit file from the pinned
// VPN-Core-Test module directory; no core source or Android API is modified.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/nodecheck/report"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	clog "github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/infra/conf"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/proxy/blackhole"
)

var coreRevision = "unknown"
var toolRevision = "unknown"

type options struct {
	Workers     int           `json:"workers"`
	NodeTimeout time.Duration `json:"node_timeout"`
	RootPEM     []byte        `json:"root_pem,omitempty"`
	Delay       *DelayOptions `json:"delay"`
}

func (o options) validate() error {
	if o.Delay == nil || o.Workers < 1 || o.Workers > 4 || o.NodeTimeout < 100*time.Millisecond || o.NodeTimeout > time.Minute || len(o.RootPEM) > 1<<20 {
		return errors.New("invalid delay worker options")
	}
	return o.Delay.validate()
}

type delayAttempt struct {
	HTTPStatus  int   `json:"http_status"`
	VerifiedTLS bool  `json:"verified_tls"`
	Bytes       int64 `json:"bytes"`
	DurationNS  int64 `json:"duration_ns"`
	DelayMS     int64 `json:"delay_ms"`
	Reused      bool  `json:"connection_reused"`
}
type delaySample struct {
	Target      string         `json:"target"`
	RealDelayNS int64          `json:"real_delay_ns"`
	RealDelayMS int64          `json:"real_delay_ms"`
	Samples     []delayAttempt `json:"samples"`
}
type result struct {
	report.Result
	Delay *delaySample `json:"delay,omitempty"`
}
type delayEngine struct {
	instance *core.Instance
	manager  outbound.Manager
	roots    *x509.CertPool
	seq      atomic.Uint64
}

func newEngine(o options) (*delayEngine, error) {
	var roots *x509.CertPool
	if len(o.RootPEM) > 0 {
		var err error
		roots, err = x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(o.RootPEM) {
			return nil, errors.New("invalid measurement CA")
		}
	}
	cfg := &core.Config{App: []*serial.TypedMessage{serial.ToTypedMessage(&dispatcher.Config{}), serial.ToTypedMessage(&proxyman.InboundConfig{}), serial.ToTypedMessage(&proxyman.OutboundConfig{})}, Outbound: []*core.OutboundHandlerConfig{{Tag: "delay-deny-default", ProxySettings: serial.ToTypedMessage(&blackhole.Config{})}}}
	instance, err := core.New(cfg)
	if err != nil {
		return nil, err
	}
	if err = instance.Start(); err != nil {
		instance.Close()
		return nil, err
	}
	return &delayEngine{instance: instance, manager: instance.GetFeature(outbound.ManagerType()).(outbound.Manager), roots: roots}, nil
}

type ownedConn struct {
	net.Conn
	once sync.Once
	err  error
}

func (c *ownedConn) Close() error { c.once.Do(func() { c.err = c.Conn.Close() }); return c.err }
func errorCode(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "TIMEOUT"
	}
	if errors.Is(err, context.Canceled) {
		return "CANCELLED"
	}
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return "TLS_CERTIFICATE"
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		return "TLS_CERTIFICATE"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "TIMEOUT"
	}
	return "TUNNEL_OR_TARGET"
}

type discardLogs struct{}

func (discardLogs) Handle(clog.Message)     {}
func (discardLogs) Severity() clog.Severity { return clog.Severity(-1) }

const MaxDelayBodyBytes int64 = 64 << 10
const DelayAttempts = 2
const DelayInterval = 100 * time.Millisecond
const DefaultDelayTarget = "https://www.google.com/generate_204"

type DelayOptions struct {
	Target string `json:"target"`
}

func (o DelayOptions) validate() error {
	u, err := url.Parse(o.Target)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || strings.ContainsAny(o.Target, "\x00\r\n\t") {
		return errors.New("real delay measurement requires an HTTPS target")
	}
	return nil
}

// Like v2rayN 7.25.6 Real Ping: two GETs on one client, a 100 ms gap,
// and the minimum positive complete-request time. Setup is outside each timer.
// Authentication, bounded bodies and a shared deadline protect ranking evidence.
func (e *delayEngine) measureDelay(parent context.Context, in report.Input, o options) result {
	started := time.Now()
	ctx, cancel := context.WithTimeout(parent, o.NodeTimeout)
	defer cancel()
	r := result{Result: report.ForInput(in, "UNMEASURED", "")}
	r.Delay = &delaySample{Target: o.Delay.Target}
	finish := func(code string) result {
		r.DurationMS = time.Since(started).Milliseconds()
		if code != "" {
			r.Failure = &report.Diagnostic{Code: code, Message: "Real Delay unavailable; connectivity eligibility is unchanged"}
		}
		return r
	}
	parsed, err := conf.ImportNodeURI(in.URI)
	if err != nil {
		return finish("DELAY_NODE_INPUT")
	}
	r.Protocol = parsed.Node.Protocol
	cfg, err := parsed.Selection.Outbound.Build()
	if err != nil {
		return finish("DELAY_NODE_BUILD")
	}
	r.ConnectionKey, err = conf.NodeConnectionKey(cfg)
	if err != nil {
		return finish("DELAY_NODE_IDENTITY")
	}
	tag := "nodedelay-" + strconv.FormatUint(e.seq.Add(1), 10)
	cfg.Tag = tag
	if err := core.AddOutboundHandler(e.instance, cfg); err != nil {
		return finish("DELAY_NODE_START")
	}
	h := e.manager.GetHandler(tag)
	defer func() { cancel(); common.Close(h); e.manager.RemoveHandler(context.Background(), tag) }()
	transport := &http.Transport{
		Proxy: nil, DisableCompression: true, ForceAttemptHTTP2: false,
		MaxIdleConns: 1, MaxIdleConnsPerHost: 1, IdleConnTimeout: o.NodeTimeout,
		TLSClientConfig:     &tls.Config{RootCAs: e.roots, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: o.NodeTimeout, ResponseHeaderTimeout: o.NodeTimeout, MaxResponseHeaderBytes: 64 << 10,
	}
	transport.DialContext = func(dctx context.Context, _, address string) (net.Conn, error) {
		destination, err := xnet.ParseDestination("tcp:" + address)
		if err != nil {
			return nil, err
		}
		conn, err := core.Dial(session.SetForcedOutboundTagToContext(dctx, tag), e.instance, destination)
		if err != nil {
			return nil, err
		}
		wrapped := &ownedConn{Conn: conn}
		context.AfterFunc(ctx, func() { wrapped.Close() })
		return wrapped, nil
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var best int64
	for attempt := 0; attempt < DelayAttempts; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(DelayInterval)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return finish("DELAY_" + errorCode(ctx.Err()))
			}
		}
		var reused atomic.Bool
		trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused.Store(info.Reused) }}
		request, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, o.Delay.Target, nil)
		if err != nil {
			return finish("DELAY_REQUEST")
		}
		request.Header.Set("User-Agent", "VPN-Nodes-Real-Delay/1")
		request.Header.Set("Accept-Encoding", "identity")
		requestStarted := time.Now()
		response, err := client.Do(request)
		r.NetworkTested = true
		if err != nil {
			if response != nil && response.Body != nil {
				response.Body.Close()
			}
			return finish("DELAY_" + errorCode(err))
		}
		sample := delayAttempt{HTTPStatus: response.StatusCode, VerifiedTLS: response.TLS != nil && response.TLS.HandshakeComplete && len(response.TLS.VerifiedChains) > 0, Reused: reused.Load()}
		code := ""
		switch {
		case !sample.VerifiedTLS:
			code = "DELAY_TLS_UNVERIFIED"
		case response.StatusCode < 200 || response.StatusCode >= 300:
			code = "DELAY_HTTP_STATUS"
		case response.Header.Get("Content-Encoding") != "" && !strings.EqualFold(response.Header.Get("Content-Encoding"), "identity"):
			code = "DELAY_CONTENT_ENCODING"
		case response.ContentLength > MaxDelayBodyBytes:
			code = "DELAY_RESPONSE_TOO_LARGE"
		}
		if code == "" {
			n, readErr := io.CopyN(io.Discard, response.Body, MaxDelayBodyBytes+1)
			sample.Bytes = n
			switch {
			case n > MaxDelayBodyBytes:
				code = "DELAY_RESPONSE_TOO_LARGE"
			case readErr != nil && readErr != io.EOF:
				code = "DELAY_INCOMPLETE_RESPONSE"
			}
		}
		sample.DurationNS = max(1, time.Since(requestStarted).Nanoseconds())
		sample.DelayMS = max(1, sample.DurationNS/int64(time.Millisecond))
		response.Body.Close()
		r.Delay.Samples = append(r.Delay.Samples, sample)
		if code != "" {
			return finish(code)
		}
		if ctx.Err() != nil || time.Since(started) > o.NodeTimeout {
			return finish("DELAY_TIMEOUT")
		}
		if best == 0 || sample.DurationNS < best {
			best = sample.DurationNS
		}
	}
	r.Delay.RealDelayNS = best
	r.Delay.RealDelayMS = max(1, best/int64(time.Millisecond))
	r.Status = "MEASURED"
	return finish("")
}

type job struct {
	Entries []report.Input `json:"entries"`
	Options options        `json:"options"`
}

func worker(ctx context.Context) error {
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 32<<20))
	decoder.DisallowUnknownFields()
	var j job
	if decoder.Decode(&j) != nil || len(j.Entries) > 256 {
		return errors.New("invalid delay job")
	}
	if err := j.Options.validate(); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("trailing delay job")
	}
	engine, err := newEngine(j.Options)
	if err != nil {
		return err
	}
	defer engine.instance.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan report.Input)
	results := make(chan result)
	var wg sync.WaitGroup
	for range j.Options.Workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for in := range jobs {
				results <- engine.measureDelay(ctx, in, j.Options)
			}
		}()
	}
	go func() {
		for _, in := range j.Entries {
			jobs <- in
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()
	encoder := json.NewEncoder(os.Stdout)
	var writeErr error
	for r := range results {
		if writeErr == nil {
			writeErr = encoder.Encode(r)
			if writeErr != nil {
				cancel()
			}
		}
	}
	return writeErr
}
func runBatch(parent context.Context, executable string, inputs []report.Input, o options, sink func(result) error) error {
	budget := time.Duration((len(inputs)+o.Workers-1)/o.Workers)*o.NodeTimeout + 15*time.Second
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-internal-worker")
	cmd.Stderr = io.Discard
	reader, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	writer, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err = cmd.Start(); err != nil {
		return err
	}
	encoded := make(chan error, 1)
	go func() { e := json.NewEncoder(writer).Encode(job{inputs, o}); writer.Close(); encoded <- e }()
	valid := map[int]report.Input{}
	for _, in := range inputs {
		valid[in.Index] = in
	}
	seen := map[int]bool{}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 128<<10)
	var protocolErr error
	for scanner.Scan() {
		var r result
		if json.Unmarshal(scanner.Bytes(), &r) != nil {
			protocolErr = errors.New("invalid delay worker response")
			cancel()
			break
		}
		in, ok := valid[r.Index]
		if !ok || seen[r.Index] || in.ID != r.ID || in.Line != r.Line || in.Source != r.Source {
			protocolErr = errors.New("foreign delay worker response")
			cancel()
			break
		}
		seen[r.Index] = true
		if e := sink(r); e != nil {
			protocolErr = e
			cancel()
			break
		}
	}
	waitErr := cmd.Wait()
	encodeErr := <-encoded
	for _, in := range inputs {
		if !seen[in.Index] {
			if e := sink(result{Result: report.ForInput(in, "RUNNER_ERROR", "DELAY_WORKER_INCOMPLETE")}); e != nil {
				return e
			}
		}
	}
	if scanner.Err() != nil || waitErr != nil || encodeErr != nil || protocolErr != nil || len(seen) != len(inputs) {
		return errors.New("delay worker incomplete; samples remain unmeasured")
	}
	return nil
}
func main() {
	clog.RegisterHandler(discardLogs{})
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := execute(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func execute(ctx context.Context) error {
	input := flag.String("input", "", "Explicit URI file")
	output := flag.String("output", "", "Empty report directory")
	target := flag.String("target", DefaultDelayTarget, "HTTPS measurement target")
	caPath := flag.String("cacert", "", "Additional trusted CA for local fixtures")
	workers := flag.Int("workers", 4, "Concurrent nodes, maximum four")
	timeout := flag.Duration("node-timeout", 5*time.Second, "Complete two-request deadline")
	internal := flag.Bool("internal-worker", false, "Private worker IPC")
	flag.Parse()
	if *internal {
		return worker(ctx)
	}
	if flag.NArg() != 0 || *input == "" || *output == "" {
		return errors.New("explicit delay input/output required")
	}
	st, err := os.Stat(*input)
	if err != nil || !st.Mode().IsRegular() {
		return errors.New("delay input must be a regular URI file")
	}
	o := options{Workers: *workers, NodeTimeout: *timeout, Delay: &DelayOptions{Target: *target}}
	if *caPath != "" {
		f, e := os.Open(*caPath)
		if e != nil {
			return errors.New("cannot open measurement CA")
		}
		o.RootPEM, err = io.ReadAll(io.LimitReader(f, (1<<20)+1))
		f.Close()
		if err != nil {
			return errors.New("cannot read measurement CA")
		}
	}
	if err = o.validate(); err != nil {
		return err
	}
	inputs, hashes, err := report.Load(*input)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(*output, 0700); err != nil {
		return err
	}
	files, err := os.ReadDir(*output)
	if err != nil {
		return err
	}
	if len(files) > 0 {
		return errors.New("delay output must be empty")
	}
	out, err := os.OpenFile(filepath.Join(*output, "results.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer out.Close()
	encoder := json.NewEncoder(out)
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	binary, err := os.Open(executable)
	if err != nil {
		return err
	}
	hash := sha256.New()
	_, err = io.Copy(hash, binary)
	binary.Close()
	if err != nil {
		return err
	}
	started := time.Now()
	statuses := map[string]int{}
	finished, processes := 0, 0
	var runErr error
	sink := func(r result) error {
		if err := encoder.Encode(r); err != nil {
			return err
		}
		finished++
		statuses[r.Status]++
		delay := int64(0)
		if r.Delay != nil {
			delay = r.Delay.RealDelayMS
		}
		code := "OK"
		if r.Failure != nil {
			code = r.Failure.Code
		}
		fmt.Fprintf(os.Stderr, "[delay %d/%d] %s node=%.12s real_delay=%dms code=%s\n", finished, len(inputs), r.Status, r.ID, delay, code)
		return nil
	}
	for start := 0; start < len(inputs); {
		end, size := start, 0
		for end < len(inputs) && end-start < 256 {
			n := len(inputs[end].URI)
			if end > start && size+n > 2<<20 {
				break
			}
			size += n
			end++
		}
		processes++
		if err := runBatch(ctx, executable, inputs[start:end], o, sink); err != nil {
			runErr = err
		}
		start = end
		if ctx.Err() != nil {
			for _, in := range inputs[start:] {
				if err := sink(result{Result: report.ForInput(in, "CANCELLED", "CANCELLED")}); err != nil {
					return err
				}
			}
			runErr = ctx.Err()
			break
		}
	}
	if err = out.Close(); err != nil {
		return err
	}
	summary := map[string]any{"schema": "xray-node-delay-v1", "revision": coreRevision, "tool_revision": toolRevision, "binary_sha256": hex.EncodeToString(hash.Sum(nil)), "input_sha256": hashes, "inventory": len(inputs), "finished": finished, "statuses": statuses, "completed": runErr == nil && finished == len(inputs), "workers": o.Workers, "worker_processes": processes, "target": o.Delay.Target, "attempts_per_node": DelayAttempts, "interval_ms": DelayInterval.Milliseconds(), "max_response_bytes": MaxDelayBodyBytes, "node_timeout_ms": o.NodeTimeout.Milliseconds(), "duration_ms": time.Since(started).Milliseconds()}
	b, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(*output, "summary.json"), append(b, '\n'), 0600); err != nil {
		return err
	}
	if err = json.NewEncoder(os.Stdout).Encode(summary); err != nil {
		return err
	}
	return runErr
}
