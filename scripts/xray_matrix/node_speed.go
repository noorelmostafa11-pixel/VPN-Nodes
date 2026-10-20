// node_speed is owned by VPN-Nodes. Build this explicit file from the pinned
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
	Speed       *SpeedOptions `json:"speed"`
}

func (o options) validate() error {
	if o.Speed == nil || o.Workers < 1 || o.Workers > 4 || o.NodeTimeout < 100*time.Millisecond || o.NodeTimeout > time.Minute || len(o.RootPEM) > 1<<20 {
		return errors.New("invalid speed worker options")
	}
	return o.Speed.validate()
}

type speedSample struct {
	Target        string `json:"target"`
	HTTPStatus    int    `json:"http_status"`
	VerifiedTLS   bool   `json:"verified_tls"`
	Bytes         int64  `json:"bytes"`
	TransferNS    int64  `json:"transfer_ns"`
	BitsPerSecond int64  `json:"bits_per_second"`
	FirstByteMS   int64  `json:"first_byte_ms"`
}
type result struct {
	report.Result
	Speed *speedSample `json:"speed,omitempty"`
}
type speedEngine struct {
	instance *core.Instance
	manager  outbound.Manager
	roots    *x509.CertPool
	seq      atomic.Uint64
}

func newEngine(o options) (*speedEngine, error) {
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
	cfg := &core.Config{App: []*serial.TypedMessage{serial.ToTypedMessage(&dispatcher.Config{}), serial.ToTypedMessage(&proxyman.InboundConfig{}), serial.ToTypedMessage(&proxyman.OutboundConfig{})}, Outbound: []*core.OutboundHandlerConfig{{Tag: "speed-deny-default", ProxySettings: serial.ToTypedMessage(&blackhole.Config{})}}}
	instance, err := core.New(cfg)
	if err != nil {
		return nil, err
	}
	if err = instance.Start(); err != nil {
		instance.Close()
		return nil, err
	}
	return &speedEngine{instance: instance, manager: instance.GetFeature(outbound.ManagerType()).(outbound.Manager), roots: roots}, nil
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

const SpeedSampleBytes int64 = 1 << 20
const DefaultSpeedTarget = "https://speed.cloudflare.com/__down?bytes=1048576"

type SpeedOptions struct {
	Target string `json:"target"`
	Bytes  int64  `json:"bytes"`
}

func (o SpeedOptions) validate() error {
	u, err := url.Parse(o.Target)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || strings.ContainsAny(o.Target, "\x00\r\n\t") || o.Bytes != SpeedSampleBytes {
		return errors.New("speed measurement requires HTTPS and a fixed 1 MiB sample")
	}
	return nil
}

// Measurement uses existing core APIs; connectivity acceptance is unchanged.
func (e *speedEngine) measureSpeed(parent context.Context, in report.Input, o options) result {
	started := time.Now()
	ctx, cancel := context.WithTimeout(parent, o.NodeTimeout)
	defer cancel()
	r := result{Result: report.ForInput(in, "UNMEASURED", "")}
	r.Speed = &speedSample{Target: o.Speed.Target}
	finish := func(code string) result {
		r.DurationMS = time.Since(started).Milliseconds()
		if code != "" {
			r.Failure = &report.Diagnostic{Code: code, Message: "Speed sample unavailable; connectivity eligibility is unchanged"}
		}
		return r
	}
	parsed, err := conf.ImportNodeURI(in.URI)
	if err != nil {
		return finish("SPEED_NODE_INPUT")
	}
	r.Protocol = parsed.Node.Protocol
	cfg, err := parsed.Selection.Outbound.Build()
	if err != nil {
		return finish("SPEED_NODE_BUILD")
	}
	r.ConnectionKey, err = conf.NodeConnectionKey(cfg)
	if err != nil {
		return finish("SPEED_NODE_IDENTITY")
	}
	tag := "nodespeed-" + strconv.FormatUint(e.seq.Add(1), 10)
	cfg.Tag = tag
	if err := core.AddOutboundHandler(e.instance, cfg); err != nil {
		return finish("SPEED_NODE_START")
	}
	h := e.manager.GetHandler(tag)
	defer func() { cancel(); common.Close(h); e.manager.RemoveHandler(context.Background(), tag) }()
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, DisableCompression: true, ForceAttemptHTTP2: false,
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
	var firstByte atomic.Int64
	requestStarted := time.Now()
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotFirstResponseByte: func() { firstByte.CompareAndSwap(0, max(1, time.Since(requestStarted).Nanoseconds())) }})
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, o.Speed.Target, nil)
	if err != nil {
		return finish("SPEED_REQUEST")
	}
	request.Header.Set("User-Agent", "VPN-Core-Node-Speed/1")
	request.Header.Set("Accept", "application/octet-stream,*/*")
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Cache-Control", "no-cache, no-store")
	response, err := client.Do(request)
	r.NetworkTested = true
	if err != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		return finish("SPEED_" + errorCode(err))
	}
	defer response.Body.Close()
	r.Speed.HTTPStatus = response.StatusCode
	r.Speed.VerifiedTLS = response.TLS != nil && response.TLS.HandshakeComplete && len(response.TLS.VerifiedChains) > 0
	if !r.Speed.VerifiedTLS {
		return finish("SPEED_TLS_UNVERIFIED")
	}
	if response.StatusCode != http.StatusOK {
		return finish("SPEED_HTTP_STATUS")
	}
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return finish("SPEED_CONTENT_ENCODING")
	}
	if response.ContentLength >= 0 && response.ContentLength != o.Speed.Bytes {
		return finish("SPEED_SAMPLE_LENGTH")
	}
	n, readErr := io.CopyN(io.Discard, response.Body, o.Speed.Bytes)
	r.Speed.Bytes = n
	first := firstByte.Load()
	r.Speed.FirstByteMS = first / int64(time.Millisecond)
	r.Speed.TransferNS = time.Since(requestStarted).Nanoseconds() - first
	if readErr != nil || n != o.Speed.Bytes {
		return finish("SPEED_INCOMPLETE_SAMPLE")
	}
	if ctx.Err() != nil || time.Since(started) > o.NodeTimeout {
		return finish("SPEED_TIMEOUT")
	}
	if first <= 0 || r.Speed.TransferNS <= 0 {
		return finish("SPEED_TIMING")
	}
	r.Speed.BitsPerSecond = n * 8 * int64(time.Second) / r.Speed.TransferNS
	if r.Speed.BitsPerSecond <= 0 {
		return finish("SPEED_TIMING")
	}
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
		return errors.New("invalid speed job")
	}
	if err := j.Options.validate(); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("trailing speed job")
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
				results <- engine.measureSpeed(ctx, in, j.Options)
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
			protocolErr = errors.New("invalid speed worker response")
			cancel()
			break
		}
		in, ok := valid[r.Index]
		if !ok || seen[r.Index] || in.ID != r.ID || in.Line != r.Line || in.Source != r.Source {
			protocolErr = errors.New("foreign speed worker response")
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
			if e := sink(result{Result: report.ForInput(in, "RUNNER_ERROR", "SPEED_WORKER_INCOMPLETE")}); e != nil {
				return e
			}
		}
	}
	if scanner.Err() != nil || waitErr != nil || encodeErr != nil || protocolErr != nil || len(seen) != len(inputs) {
		return errors.New("speed worker incomplete; samples remain unmeasured")
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
	target := flag.String("target", DefaultSpeedTarget, "HTTPS measurement target")
	caPath := flag.String("cacert", "", "Additional trusted CA for local fixtures")
	workers := flag.Int("workers", 4, "Concurrent nodes, maximum four")
	timeout := flag.Duration("node-timeout", 8*time.Second, "Complete sample deadline")
	internal := flag.Bool("internal-worker", false, "Private worker IPC")
	flag.Parse()
	if *internal {
		return worker(ctx)
	}
	if flag.NArg() != 0 || *input == "" || *output == "" {
		return errors.New("explicit speed input/output required")
	}
	st, err := os.Stat(*input)
	if err != nil || !st.Mode().IsRegular() {
		return errors.New("speed input must be a regular URI file")
	}
	o := options{Workers: *workers, NodeTimeout: *timeout, Speed: &SpeedOptions{Target: *target, Bytes: SpeedSampleBytes}}
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
		return errors.New("speed output must be empty")
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
		bps := int64(0)
		if r.Speed != nil {
			bps = r.Speed.BitsPerSecond
		}
		code := "OK"
		if r.Failure != nil {
			code = r.Failure.Code
		}
		fmt.Fprintf(os.Stderr, "[speed %d/%d] %s node=%.12s download=%.3fMbps code=%s\n", finished, len(inputs), r.Status, r.ID, float64(bps)/1e6, code)
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
	summary := map[string]any{"schema": "xray-node-speed-v1", "revision": coreRevision, "tool_revision": toolRevision, "binary_sha256": hex.EncodeToString(hash.Sum(nil)), "input_sha256": hashes, "inventory": len(inputs), "finished": finished, "statuses": statuses, "completed": runErr == nil && finished == len(inputs), "workers": o.Workers, "worker_processes": processes, "target": o.Speed.Target, "sample_bytes": SpeedSampleBytes, "node_timeout_ms": o.NodeTimeout.Milliseconds(), "duration_ms": time.Since(started).Milliseconds()}
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
