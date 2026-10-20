package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/nodecheck/report"
	clog "github.com/xtls/xray-core/common/log"
)

const testDelayID = "11111111-2222-4333-8444-555555555555"

func delayInput(uri string, index int) report.Input {
	h := sha256.Sum256([]byte(uri))
	return report.Input{URI: uri, Index: index, Line: index + 1, Source: "nodes.txt", ID: hex.EncodeToString(h[:])}
}

// Independent VLESS wire peer. It can reach only the exact local HTTPS origin;
// invalid credentials cannot cause an HTTP request or a direct fallback.
func delayPeer(t *testing.T, origin *httptest.Server) (string, *atomic.Int32) {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := strings.TrimPrefix(origin.URL, "https://")
	expectedID, _ := hex.DecodeString(strings.ReplaceAll(testDelayID, "-", ""))
	var accepted atomic.Int32
	var mu sync.Mutex
	active := map[net.Conn]bool{}
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			active[c] = true
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				defer func() { mu.Lock(); delete(active, c); mu.Unlock() }()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				header := make([]byte, 18)
				if _, err := io.ReadFull(c, header); err != nil || header[0] != 0 || !bytes.Equal(header[1:17], expectedID) {
					return
				}
				if _, err := io.CopyN(io.Discard, c, int64(header[17])); err != nil {
					return
				}
				meta := make([]byte, 4)
				if _, err := io.ReadFull(c, meta); err != nil || meta[0] != 1 || meta[3] != 1 {
					return
				}
				ip := make([]byte, 4)
				if _, err := io.ReadFull(c, ip); err != nil {
					return
				}
				address := net.JoinHostPort(net.IP(ip).String(), strconv.Itoa(int(meta[1])<<8|int(meta[2])))
				if address != target {
					return
				}
				u, err := net.DialTimeout("tcp4", address, time.Second)
				if err != nil {
					return
				}
				defer u.Close()
				accepted.Add(1)
				if _, err := c.Write([]byte{0, 0}); err != nil {
					return
				}
				upstreamDone := make(chan struct{})
				go func() { io.Copy(u, c); u.Close(); close(upstreamDone) }()
				io.Copy(c, u)
				c.Close()
				<-upstreamDone
			}()
		}
	}()
	t.Cleanup(func() {
		l.Close()
		<-done
		mu.Lock()
		for c := range active {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return "vless://" + testDelayID + "@" + l.Addr().String() + "?security=none", &accepted
}

func delayOptions(origin *httptest.Server) options {
	return options{Workers: 4, NodeTimeout: 2 * time.Second, Delay: &DelayOptions{Target: origin.URL},
		RootPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw})}
}

func delayEngineFor(t *testing.T, o options) *delayEngine {
	t.Helper()
	clog.RegisterHandler(discardLogs{})
	e, err := newEngine(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.instance.Close() })
	return e
}

func TestRealDelayMinimumAndConnectionReuse(t *testing.T) {
	var count atomic.Int32
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if count.Add(1) == 1 {
			time.Sleep(55 * time.Millisecond)
		} else {
			time.Sleep(5 * time.Millisecond)
		}
		w.WriteHeader(204)
	}))
	defer origin.Close()
	uri, tunnels := delayPeer(t, origin)
	o := delayOptions(origin)
	r := delayEngineFor(t, o).measureDelay(context.Background(), delayInput(uri, 0), o)
	if r.Status != "MEASURED" || len(r.Delay.Samples) != 2 || count.Load() != 2 || tunnels.Load() != 1 {
		t.Fatalf("not two requests on the real tunnel: %+v count=%d tunnels=%d", r, count.Load(), tunnels.Load())
	}
	a, b := r.Delay.Samples[0], r.Delay.Samples[1]
	if a.Reused || !b.Reused || a.Bytes != 0 || b.Bytes != 0 || !a.VerifiedTLS || !b.VerifiedTLS {
		t.Fatal("missing reuse/empty HTTPS proof", r.Delay)
	}
	if r.Delay.RealDelayNS != min(a.DurationNS, b.DurationNS) || r.Delay.RealDelayMS != max(1, r.Delay.RealDelayNS/int64(time.Millisecond)) {
		t.Fatal("score is not the minimum complete request duration")
	}
	if time.Duration(r.DurationMS)*time.Millisecond < DelayInterval {
		t.Fatal("request gap missing")
	}
}

func TestRealDelayFailuresStayUnmeasured(t *testing.T) {
	for _, tc := range []string{"http403", "redirect", "large", "chunked-large", "partial", "compression", "second-fails", "untrusted", "wrong-node", "timeout"} {
		t.Run(tc, func(t *testing.T) {
			var requests atomic.Int32
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := requests.Add(1)
				switch tc {
				case "http403":
					w.WriteHeader(403)
				case "redirect":
					http.Redirect(w, r, "https://other.invalid", 302)
				case "large":
					w.Header().Set("Content-Length", "65537")
					w.WriteHeader(200)
				case "chunked-large":
					w.WriteHeader(200)
					w.(http.Flusher).Flush()
					w.Write(bytes.Repeat([]byte{'x'}, 65537))
				case "partial":
					w.Header().Set("Content-Length", "128")
					w.Write([]byte("short"))
				case "compression":
					w.Header().Set("Content-Encoding", "gzip")
					w.WriteHeader(200)
				case "second-fails":
					if n == 1 {
						w.WriteHeader(204)
					} else {
						w.WriteHeader(500)
					}
				case "timeout":
					select {
					case <-r.Context().Done():
					case <-time.After(time.Second):
					}
					w.WriteHeader(204)
				default:
					w.WriteHeader(204)
				}
			}))
			defer origin.Close()
			uri, _ := delayPeer(t, origin)
			o := delayOptions(origin)
			if tc == "untrusted" {
				o.RootPEM = nil
			}
			if tc == "wrong-node" {
				uri = strings.Replace(uri, testDelayID, "22222222-2222-4222-8222-222222222222", 1)
			}
			if tc == "timeout" {
				o.NodeTimeout = 250 * time.Millisecond
			}
			r := delayEngineFor(t, o).measureDelay(context.Background(), delayInput(uri, 0), o)
			if r.Status != "UNMEASURED" || r.Failure == nil || r.Delay.RealDelayNS != 0 || r.Delay.RealDelayMS != 0 {
				t.Fatalf("failure received a ranking score: %+v", r)
			}
			if (tc == "untrusted" || tc == "wrong-node") && requests.Load() != 0 {
				t.Fatal("invalid TLS/credentials reached the target")
			}
		})
	}
}

func TestRealDelayCLI(t *testing.T) {
	helper := os.Getenv("DELAY_TEST_BINARY")
	if helper == "" {
		t.Skip("set DELAY_TEST_BINARY to the explicitly built VPN-Nodes helper")
	}
	var requests, active, peak atomic.Int32
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := active.Add(1)
		defer active.Add(-1)
		requests.Add(1)
		for p := peak.Load(); n > p; p = peak.Load() {
			if peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
		w.WriteHeader(204)
	}))
	defer origin.Close()
	uri, _ := delayPeer(t, origin)
	root := t.TempDir()
	input, ca, out := filepath.Join(root, "nodes.txt"), filepath.Join(root, "ca.pem"), filepath.Join(root, "report")
	var lines strings.Builder
	for i := 0; i < 8; i++ {
		fmt.Fprintf(&lines, "%s#synthetic-%d\n", uri, i)
	}
	if err := os.WriteFile(input, []byte(lines.String()), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ca, delayOptions(origin).RootPEM, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, helper, "-input", input, "-output", out, "-target", origin.URL, "-cacert", ca, "-workers", "4", "-node-timeout", "2s")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(err, string(output))
	}
	if requests.Load() != 16 || peak.Load() > 4 || peak.Load() < 2 {
		t.Fatal("wrong request count/concurrency", requests.Load(), peak.Load())
	}
	if strings.Contains(string(output), testDelayID) || strings.Contains(string(output), "vless://") {
		t.Fatal("credentials in CLI output")
	}
	f, err := os.Open(filepath.Join(out, "results.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		var r result
		if json.Unmarshal(scanner.Bytes(), &r) != nil || r.Status != "MEASURED" || r.Delay.RealDelayMS <= 0 || len(r.Delay.Samples) != 2 {
			t.Fatal("invalid CLI result")
		}
		count++
	}
	if scanner.Err() != nil || count != 8 {
		t.Fatal("CLI coverage incomplete", count, scanner.Err())
	}
	var summary map[string]any
	b, err := os.ReadFile(filepath.Join(out, "summary.json"))
	if err != nil || json.Unmarshal(b, &summary) != nil {
		t.Fatal("missing CLI summary", err)
	}
	if summary["schema"] != "xray-node-delay-v1" || summary["attempts_per_node"] != float64(2) || summary["interval_ms"] != float64(100) || summary["completed"] != true {
		t.Fatal("wrong CLI measurement policy", summary)
	}
}
