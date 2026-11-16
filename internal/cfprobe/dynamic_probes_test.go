package cfprobe

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func testDynamicCatalog() DynamicProbeCatalog {
	c := DynamicProbeCatalog{Enabled: true, Groups: []DynamicProbeGroup{}}
	for i, family := range []string{"ipv4", "ipv6", "auto"} {
		g := DynamicProbeGroup{ID: fmt.Sprintf("g_%d", i), Name: family, Family: family, Targets: []DynamicProbeTarget{}}
		for n := 0; n < 6; n++ {
			address := "1.1.1.1:443"
			if family == "ipv6" {
				address = "[2606:4700:4700::1111]:443"
			}
			g.Targets = append(g.Targets, DynamicProbeTarget{ID: fmt.Sprintf("p_%d_%d", i, n), Name: "线路", Address: address, Enabled: true})
		}
		c.Groups = append(c.Groups, g)
	}
	return c
}

func TestDynamicConfigValidationAndAutomaticFamilies(t *testing.T) {
	c := testDynamicCatalog()
	raw, _ := json.Marshal(c)
	parsed, s, err := parseDynamicProbes(string(raw), `{"mode":"auto","targets":[]}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		v4, v6 string
		count  int
	}{{"1", "0", 12}, {"0", "1", 12}, {"1", "1", 18}, {"0", "0", 0}} {
		if got := len(selectDynamicProbes(parsed, s, tt.v4, tt.v6)); got != tt.count {
			t.Fatalf("%s/%s: %d", tt.v4, tt.v6, got)
		}
	}
	s = DynamicProbeSelection{Mode: "manual", Targets: []string{"p_1_0"}}
	if got := selectDynamicProbes(parsed, s, "1", "0"); len(got) != 1 || got[0].Family != "ipv6" {
		t.Fatal(got)
	}
	s.Targets = nil
	if len(selectDynamicProbes(parsed, s, "1", "1")) != 0 {
		t.Fatal("manual empty selection reset")
	}
	for _, bad := range []string{string(raw) + " {}", string(raw) + " garbage"} {
		if _, _, err := parseDynamicProbes(bad, ""); err == nil {
			t.Fatal("accepted trailing data")
		}
	}
	for _, address := range []string{"999.1.1.1", "bad-.host", "host:0", "https://host", "[::1]"} {
		c.Groups[0].Targets[0].Address = address
		invalid, _ := json.Marshal(c)
		if _, _, err := parseDynamicProbes(string(invalid), ""); err == nil {
			t.Fatal("accepted invalid target", address)
		}
	}
}

func TestDynamicCycleLimitsConcurrencyAndPublishesBeforeBatchCompletes(t *testing.T) {
	targets := selectDynamicProbes(testDynamicCatalog(), DynamicProbeSelection{Mode: "auto"}, "1", "1")
	var running, maxRunning, published atomic.Int32
	result := runDynamicProbeCycle(context.Background(), targets, func(target DynamicProbeTarget) DynamicProbeSample {
		active := running.Add(1)
		for {
			old := maxRunning.Load()
			if active <= old || maxRunning.CompareAndSwap(old, active) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		running.Add(-1)
		return DynamicProbeSample{Timestamp: time.Now().UnixMilli(), Latency: 0, Loss: 0}
	}, func(_ string, _ DynamicProbeSample) { published.Add(1) })
	if maxRunning.Load() > 4 || maxRunning.Load() < 2 || len(result) != 18 || published.Load() != 18 {
		t.Fatalf("concurrency %d, results %d, published %d", maxRunning.Load(), len(result), published.Load())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := runDynamicProbeCycle(ctx, targets, func(DynamicProbeTarget) DynamicProbeSample { t.Error("ran cancelled job"); return DynamicProbeSample{} }, nil); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestDynamicSnapshotExpiresSamplesAndConfigChangesClearResults(t *testing.T) {
	cfg := Config{ProbeCatalog: "catalog", ProbeSelection: "selection", PingMode: "tcp"}
	now := time.Now().UnixMilli()
	a := &Agent{dynamicProbeConfig: "catalogselectiontcp", dynamicProbes: map[string]DynamicProbeSample{"p_live": {Timestamp: now, Latency: 0, Loss: 0}, "p_old": {Timestamp: now - 121000, Latency: 1, Loss: 0}}}
	if got := a.dynamicProbeSnapshot(cfg); len(got) != 1 || got["p_live"].Latency != 0 {
		t.Fatal(got)
	}
	cfg.ProbeSelection = "new selection"
	if got := a.dynamicProbeSnapshot(cfg); got == nil || len(got) != 0 {
		t.Fatal("must send empty snapshot to clear removed probes", got)
	}
}

func TestDynamicBufferedSamplesUseCalibratedTimeWithoutMutatingBuffer(t *testing.T) {
	now := time.Now()
	probes := map[string]DynamicProbeSample{"p_zero": {Timestamp: now.UnixMilli(), Latency: 0, Loss: 0}}
	a := &Agent{samples: []metricSample{{at: now, metrics: map[string]any{"probes": probes}}}}
	a.clock.calibration = &clockCalibration{anchor: now, accurateAtAnchor: now.UnixMilli() + 60000}
	samples := a.samplesForReport()
	result := samples[0]["metrics"].(map[string]any)["probes"].(map[string]DynamicProbeSample)
	if result["p_zero"].Timestamp != now.UnixMilli()+60000 || probes["p_zero"].Timestamp != now.UnixMilli() {
		t.Fatal("wrong timestamp or mutated buffer")
	}
	wire := a.metricsForReport(Metrics{Probes: probes}, now)["probes"].(map[string]DynamicProbeSample)
	if !reflect.DeepEqual(wire, result) {
		t.Fatal(wire, result)
	}
}

func TestDynamicWSSObjectConfigAndFamilyDNS(t *testing.T) {
	c := testDynamicCatalog()
	body, _, _ := wssConfigPayload(map[string]any{"schema_version": 8, "probe_catalog": c, "probe_selection": DynamicProbeSelection{Mode: "auto", Targets: []string{}}})
	values, err := url.ParseQuery(body)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseDynamicProbes(values.Get("probe_catalog"), values.Get("probe_selection")); err != nil {
		t.Fatal(err)
	}
	oldLookup := lookupIP
	defer func() { lookupIP = oldLookup }()
	lookupIP = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("1.2.3.4")}, {IP: net.ParseIP("2001:db8::1")}}, nil
	}
	for _, tt := range []struct{ family, want string }{{"ipv4", "1.2.3.4:443"}, {"ipv6", "[2001:db8::1]:443"}} {
		got, err := resolveDynamicProbe(DynamicProbeTarget{Address: "dynamic-family-test.invalid:443", Family: tt.family})
		if err != nil || got != tt.want {
			t.Fatal(got, err)
		}
	}
}
