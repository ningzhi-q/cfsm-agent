package cfprobe

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const maxRemoteConfigBytes = 65536
const dynamicProbeConcurrency = 4

type DynamicProbeTarget struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
	Enabled bool   `json:"enabled"`
	Family  string `json:"-"`
}
type DynamicProbeGroup struct {
	ID      string               `json:"id"`
	Name    string               `json:"name"`
	Family  string               `json:"family"`
	Targets []DynamicProbeTarget `json:"targets"`
}
type DynamicProbeCatalog struct {
	Enabled bool                `json:"enabled"`
	Groups  []DynamicProbeGroup `json:"groups"`
}
type DynamicProbeSelection struct {
	Mode    string   `json:"mode"`
	Targets []string `json:"targets"`
}
type DynamicProbeSample struct {
	Timestamp int64 `json:"ts"`
	Latency   any   `json:"latency"`
	Loss      any   `json:"loss"`
}

var dynamicProbeID = regexp.MustCompile(`^p_[a-zA-Z0-9_-]{1,60}$`)
var dynamicGroupID = regexp.MustCompile(`^g_[a-zA-Z0-9_-]{1,60}$`)
var dynamicHost = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
var dynamicIPv4Like = regexp.MustCompile(`^(?:\d+\.){3}\d+$`)
var dynamicHostLabel = regexp.MustCompile(`^[a-zA-Z0-9_](?:[a-zA-Z0-9_-]*[a-zA-Z0-9_])?$`)

func validDynamicHostname(host string) bool {
	if len(host) > 50 || !dynamicHost.MatchString(host) || dynamicIPv4Like.MatchString(host) {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !dynamicHostLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func parseDynamicProbes(catalogRaw, selectionRaw string) (DynamicProbeCatalog, DynamicProbeSelection, error) {
	catalog := DynamicProbeCatalog{Groups: []DynamicProbeGroup{}}
	selection := DynamicProbeSelection{Mode: "auto", Targets: []string{}}
	if len(url.QueryEscape(catalogRaw))+len(url.QueryEscape(selectionRaw)) > maxRemoteConfigBytes-1024 {
		return catalog, selection, errors.New("probe configuration too large")
	}
	decode := func(raw string, output any) error {
		if raw == "" {
			return nil
		}
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(output); err != nil {
			return err
		}
		if err := dec.Decode(new(any)); err != io.EOF {
			return errors.New("multiple probe configurations")
		}
		return nil
	}
	if err := decode(catalogRaw, &catalog); err != nil {
		return catalog, selection, err
	}
	if err := decode(selectionRaw, &selection); err != nil {
		return catalog, selection, err
	}
	if selection.Mode != "auto" && selection.Mode != "manual" {
		return catalog, selection, errors.New("invalid probe selection mode")
	}
	for _, id := range selection.Targets {
		if !dynamicProbeID.MatchString(id) {
			return catalog, selection, errors.New("invalid selected probe")
		}
	}
	ids := map[string]bool{}
	for _, group := range catalog.Groups {
		if !dynamicGroupID.MatchString(group.ID) || ids[group.ID] || strings.TrimSpace(group.Name) == "" || utf8.RuneCountInString(group.Name) > 80 || (group.Family != "ipv4" && group.Family != "ipv6" && group.Family != "auto") {
			return catalog, selection, errors.New("invalid probe group")
		}
		ids[group.ID] = true
		for _, target := range group.Targets {
			host, _, err := splitProbeTarget(target.Address, defaultMetricsTCPPort)
			ip := net.ParseIP(host)
			if err != nil || len(target.Address) > 60 || strings.TrimSpace(target.Name) == "" || utf8.RuneCountInString(target.Name) > 80 || !dynamicProbeID.MatchString(target.ID) || ids[target.ID] || (ip == nil && !validDynamicHostname(host)) {
				return catalog, selection, errors.New("invalid probe target")
			}
			if ip != nil && ((group.Family == "ipv4" && ip.To4() == nil) || (group.Family == "ipv6" && ip.To4() != nil)) {
				return catalog, selection, errors.New("probe address family mismatch")
			}
			ids[target.ID] = true
		}
	}
	return catalog, selection, nil
}

func selectDynamicProbes(catalog DynamicProbeCatalog, selection DynamicProbeSelection, ipv4, ipv6 string) []DynamicProbeTarget {
	// networkWorker stores the discovered addresses. The public backend turns them
	// into "1"/"0" flags, so selection must also accept the internal IP values.
	v4IP, v6IP := net.ParseIP(ipv4), net.ParseIP(ipv6)
	hasIPv4 := ipv4 == "1" || (v4IP != nil && v4IP.To4() != nil)
	hasIPv6 := ipv6 == "1" || (v6IP != nil && v6IP.To4() == nil)
	result := []DynamicProbeTarget{}
	selected := map[string]bool{}
	for _, id := range selection.Targets {
		selected[id] = true
	}
	if !catalog.Enabled {
		return result
	}
	for _, group := range catalog.Groups {
		auto := (group.Family == "ipv4" && hasIPv4) || (group.Family == "ipv6" && hasIPv6) || (group.Family == "auto" && (hasIPv4 || hasIPv6))
		for _, target := range group.Targets {
			if target.Enabled && ((selection.Mode == "auto" && auto) || (selection.Mode == "manual" && selected[target.ID])) {
				target.Family = group.Family
				if target.Family == "auto" {
					if hasIPv4 && !hasIPv6 {
						target.Family = "ipv4"
					} else if hasIPv6 && !hasIPv4 {
						target.Family = "ipv6"
					}
				}
				result = append(result, target)
			}
		}
	}
	return result
}

func resolveDynamicProbe(target DynamicProbeTarget) (string, error) {
	host, port, err := splitProbeTarget(target.Address, defaultMetricsTCPPort)
	if err != nil {
		return "", err
	}
	if ip := net.ParseIP(host); ip != nil {
		return net.JoinHostPort(host, intString(port)), nil
	}
	key := strings.ToLower(host) + "|" + target.Family
	now := time.Now()
	dnsCacheMu.RLock()
	entry, ok := dnsCache[key]
	dnsCacheMu.RUnlock()
	if ok && now.Before(entry.expiresAt) {
		return net.JoinHostPort(entry.ip, intString(port)), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addresses, err := lookupIP(ctx, host)
	if err != nil {
		return "", err
	}
	for _, address := range addresses {
		if address.IP == nil || (target.Family == "ipv4" && address.IP.To4() == nil) || (target.Family == "ipv6" && address.IP.To4() != nil) {
			continue
		}
		ip := address.IP.String()
		dnsCacheMu.Lock()
		dnsCache[key] = dnsCacheEntry{ip: ip, expiresAt: now.Add(dnsCacheTTL)}
		dnsCacheMu.Unlock()
		return net.JoinHostPort(ip, intString(port)), nil
	}
	return "", errors.New("no address for selected network family")
}

// A fixed worker pool caps sockets and goroutines. It runs independently of metric collection;
// long probe cycles never delay CPU/network reports or overlap another probe cycle.
func runDynamicProbeCycle(ctx context.Context, targets []DynamicProbeTarget, measure func(DynamicProbeTarget) DynamicProbeSample, publish func(string, DynamicProbeSample)) map[string]DynamicProbeSample {
	result := map[string]DynamicProbeSample{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	jobs := make(chan DynamicProbeTarget)
	for i := 0; i < dynamicProbeConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				if ctx.Err() != nil {
					return
				}
				sample := measure(target)
				mu.Lock()
				result[target.ID] = sample
				mu.Unlock()
				if publish != nil && ctx.Err() == nil {
					publish(target.ID, sample)
				}
			}
		}()
	}
	for _, target := range targets {
		select {
		case jobs <- target:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return result
		}
	}
	close(jobs)
	wg.Wait()
	return result
}

func (a *Agent) dynamicProbeWorker(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var last time.Time
	var previous string
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			cfg := a.configSnapshot()
			key := cfg.ProbeCatalog + cfg.ProbeSelection + cfg.PingMode
			catalog, selection, err := parseDynamicProbes(cfg.ProbeCatalog, cfg.ProbeSelection)
			if err != nil {
				continue
			}
			a.mu.RLock()
			ipv4, ipv6 := a.probes.IPv4, a.probes.IPv6
			a.mu.RUnlock()
			cycleKey := key + ipv4 + ipv6
			if cycleKey == previous && !last.IsZero() && now.Sub(last) < metricsProbeInterval {
				continue
			}
			if catalog.Enabled && selection.Mode == "auto" && ipv4 == "" && ipv6 == "" {
				continue
			}
			targets := selectDynamicProbes(catalog, selection, ipv4, ipv6)
			a.mu.Lock()
			if a.dynamicProbeConfig != key {
				a.dynamicProbes = map[string]DynamicProbeSample{}
			}
			active := map[string]bool{}
			for _, target := range targets {
				active[target.ID] = true
			}
			for id := range a.dynamicProbes {
				if !active[id] {
					delete(a.dynamicProbes, id)
				}
			}
			a.dynamicProbeConfig = key
			a.mu.Unlock()
			runDynamicProbeCycle(ctx, targets, func(target DynamicProbeTarget) DynamicProbeSample {
				address, err := resolveDynamicProbe(target)
				sample := DynamicProbeSample{Timestamp: time.Now().UnixMilli(), Loss: 100}
				if err != nil {
					return sample
				}
				probe := measureProbe(cfg.PingMode, address, metricsProbeSampleCount, defaultMetricsTCPPort, a.log)
				sample.Timestamp = time.Now().UnixMilli()
				sample.Loss = probe.Loss
				if probe.OK {
					sample.Latency = probe.RTTMs
				}
				return sample
			}, func(id string, sample DynamicProbeSample) {
				current := a.configSnapshot()
				if current.ProbeCatalog+current.ProbeSelection+current.PingMode != key {
					return
				}
				a.mu.Lock()
				a.dynamicProbes[id] = sample
				a.mu.Unlock()
			})
			if ctx.Err() != nil {
				return
			}
			last = time.Now()
			previous = cycleKey
		}
	}
}

func (a *Agent) dynamicProbeSnapshot(cfg Config) map[string]DynamicProbeSample {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.dynamicProbeConfig != cfg.ProbeCatalog+cfg.ProbeSelection+cfg.PingMode {
		if cfg.ProbeCatalog == "" {
			return nil
		}
		return map[string]DynamicProbeSample{}
	}
	result := map[string]DynamicProbeSample{}
	now := time.Now().UnixMilli()
	for id, sample := range a.dynamicProbes {
		if now-sample.Timestamp <= 120000 {
			result[id] = sample
		}
	}
	return result
}
