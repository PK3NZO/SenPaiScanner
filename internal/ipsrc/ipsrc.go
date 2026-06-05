package ipsrc

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	_ "embed"

	"github.com/matinsenpai/senpaiscanner/internal/provider"
)

//go:embed ranges_v4.txt
var builtinV4 string

//go:embed ranges_v6.txt
var builtinV6 string

//go:embed ranges_cloudfront_v4.txt
var builtinCloudFrontV4 string

//go:embed ranges_cloudfront_v6.txt
var builtinCloudFrontV6 string

//go:embed ranges_gcore_v4.txt
var builtinGcoreV4 string

//go:embed ranges_fastly_v4.txt
var builtinFastlyV4 string

const (
	cfIPsV4URL = "https://www.cloudflare.com/ips-v4/"
	cfIPsV6URL = "https://www.cloudflare.com/ips-v6/"
)

// Source holds the CIDR ranges used for IP generation.
type Source struct {
	v4Nets []*net.IPNet
	v6Nets []*net.IPNet
	rng    *rand.Rand
}

// Options controls how a Source is built.
type Options struct {
	// UseBuiltin controls whether embedded provider ranges are loaded before
	// any extra CIDRs are added. Set it to false when user-provided CIDRs should
	// be treated as an exact scan scope rather than as additions to the provider's
	// full published ranges.
	UseBuiltin bool
	// Provider selects which embedded range set to use.
	Provider provider.Kind
}

// New builds a Source from the embedded provider ranges plus optional extra
// CIDRs.
func New(useV4, useV6 bool, extra []string) (*Source, error) {
	return NewWithOptions(useV4, useV6, extra, Options{UseBuiltin: true})
}

// NewWithOptions builds a Source with explicit control over built-in ranges.
func NewWithOptions(useV4, useV6 bool, extra []string, opts Options) (*Source, error) {
	s := &Source{
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
	}

	if opts.UseBuiltin && useV4 {
		nets, err := parseLines(builtinRangesV4(opts.Provider))
		if err != nil {
			return nil, err
		}
		s.v4Nets = nets
	}

	if opts.UseBuiltin && useV6 {
		nets, err := parseLines(builtinRangesV6(opts.Provider))
		if err != nil {
			return nil, err
		}
		s.v6Nets = nets
	}

	for _, cidr := range extra {
		_, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		if ipNet.IP.To4() != nil {
			s.v4Nets = append(s.v4Nets, ipNet)
		} else {
			s.v6Nets = append(s.v6Nets, ipNet)
		}
	}

	if len(s.v4Nets)+len(s.v6Nets) == 0 {
		return nil, fmt.Errorf("no IP ranges available (enable --v4 and/or --v6)")
	}

	return s, nil
}

// IPv4Nets returns the loaded IPv4 CIDR blocks (read-only slice header).
func (s *Source) IPv4Nets() []*net.IPNet {
	return s.v4Nets
}

// CountUpTo returns the number of unique addresses available up to limit.
// If the source has more than limit addresses, limit is returned.
func (s *Source) CountUpTo(limit int) int {
	if limit <= 0 {
		return 0
	}
	if ips, ok := s.enumerateIfAtMost(limit); ok {
		return len(ips)
	}
	return limit
}

// Random returns a single random IP from the configured ranges.
func (s *Source) Random() net.IP {
	target := s.weightedRandomNet()
	if target == nil {
		return nil
	}
	return randomFromNet(target, s.rng)
}

// Stream emits random IPs on the returned channel until ctx is cancelled or
// count IPs have been sent (count <= 0 means unlimited).
//
// Each IP is emitted at most once per call: duplicates are silently skipped.
// If the requested count is larger than a finite embedded range set, Stream
// emits every available address once and then closes.
func (s *Source) Stream(ctx context.Context, count int) <-chan net.IP {
	ch := make(chan net.IP, 64)
	go func() {
		defer close(ch)
		if count > 0 {
			if ips, ok := s.enumerateIfAtMost(count); ok {
				s.rng.Shuffle(len(ips), func(i, j int) {
					ips[i], ips[j] = ips[j], ips[i]
				})
				for _, ip := range ips {
					select {
					case <-ctx.Done():
						return
					case ch <- ip:
					}
				}
				return
			}
		}

		seen := make(map[string]struct{})
		sent := 0
		for {
			if count > 0 && sent >= count {
				return
			}
			ip := s.Random()
			key := ip.String()
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			select {
			case <-ctx.Done():
				return
			case ch <- ip:
				sent++
			}
		}
	}()
	return ch
}

// FromCIDR expands a single CIDR string into a channel of all its IPs.
// For large ranges use caution — prefer Stream for /16 and above.
func FromCIDR(ctx context.Context, cidr string) (<-chan net.IP, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	ch := make(chan net.IP, 128)
	go func() {
		defer close(ch)
		for ip := cloneIP(ipNet.IP); ipNet.Contains(ip); incrementIP(ip) {
			select {
			case <-ctx.Done():
				return
			case ch <- cloneIP(ip):
			}
		}
	}()
	return ch, nil
}

// UpdateRanges fetches the latest Cloudflare IP ranges from cloudflare.com.
// Returns the raw CIDRs for v4 and v6.
func UpdateRanges(ctx context.Context) (v4, v6 []string, err error) {
	fetch := func(url string) ([]string, error) {
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if e != nil {
			return nil, e
		}
		resp, e := http.DefaultClient.Do(req)
		if e != nil {
			return nil, fmt.Errorf("fetch %s: %w", url, e)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected status %d for %s", resp.StatusCode, url)
		}
		var lines []string
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			if l != "" {
				lines = append(lines, l)
			}
		}
		return lines, sc.Err()
	}

	v4, err = fetch(cfIPsV4URL)
	if err != nil {
		return
	}
	v6, err = fetch(cfIPsV6URL)
	return
}

// V4Ranges returns the currently loaded v4 nets as CIDR strings.
func (s *Source) V4Ranges() []string {
	return netsToStrings(s.v4Nets)
}

// V6Ranges returns the currently loaded v6 nets as CIDR strings.
func (s *Source) V6Ranges() []string {
	return netsToStrings(s.v6Nets)
}

// MarshalJSON allows serialising the current source ranges.
func (s *Source) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string][]string{
		"v4": s.V4Ranges(),
		"v6": s.V6Ranges(),
	})
}

// --- helpers ----------------------------------------------------------------

func parseLines(raw string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, ipNet, err := net.ParseCIDR(line)
		if err != nil {
			return nil, fmt.Errorf("parsing %q: %w", line, err)
		}
		nets = append(nets, ipNet)
	}
	return nets, sc.Err()
}

func (s *Source) enumerateIfAtMost(limit int) ([]net.IP, bool) {
	if limit <= 0 {
		return nil, false
	}
	all := append([]*net.IPNet{}, s.v4Nets...)
	all = append(all, s.v6Nets...)

	var ips []net.IP
	seen := make(map[string]struct{})
	for _, n := range all {
		ones, bits := n.Mask.Size()
		if ones < 0 || bits < 0 {
			return nil, false
		}
		hostBits := bits - ones
		if hostBits >= 31 {
			return nil, false
		}
		size := 1 << uint(hostBits)
		if len(ips)+size > limit {
			return nil, false
		}
		for ip := cloneIP(n.IP); n.Contains(ip); incrementIP(ip) {
			key := ip.String()
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			ips = append(ips, cloneIP(ip))
		}
	}
	return ips, true
}

func (s *Source) weightedRandomNet() *net.IPNet {
	if len(s.v4Nets)+len(s.v6Nets) == 0 {
		return nil
	}

	var total uint64
	weights := make([]uint64, len(s.v4Nets)+len(s.v6Nets))
	for i, n := range s.v4Nets {
		weight := netAddressCount(n)
		if weight == 0 {
			continue
		}
		if total > ^uint64(0)-weight {
			weight = ^uint64(0) - total
		}
		weights[i] = weight
		total += weight
		if total == ^uint64(0) {
			break
		}
	}
	if total != ^uint64(0) {
		offset := len(s.v4Nets)
		for i, n := range s.v6Nets {
			weight := netAddressCount(n)
			if weight == 0 {
				continue
			}
			if total > ^uint64(0)-weight {
				weight = ^uint64(0) - total
			}
			weights[offset+i] = weight
			total += weight
			if total == ^uint64(0) {
				break
			}
		}
	}
	if total == 0 {
		if len(s.v4Nets) > 0 {
			return s.v4Nets[s.rng.Intn(len(s.v4Nets))]
		}
		return s.v6Nets[s.rng.Intn(len(s.v6Nets))]
	}

	choice := randomUint64Below(s.rng, total)
	for i, weight := range weights {
		if weight == 0 {
			continue
		}
		if choice < weight {
			if i < len(s.v4Nets) {
				return s.v4Nets[i]
			}
			return s.v6Nets[i-len(s.v4Nets)]
		}
		choice -= weight
	}
	if len(s.v6Nets) > 0 {
		return s.v6Nets[len(s.v6Nets)-1]
	}
	return s.v4Nets[len(s.v4Nets)-1]
}

func netAddressCount(n *net.IPNet) uint64 {
	ones, bits := n.Mask.Size()
	if ones < 0 || bits < 0 {
		return 0
	}
	hostBits := bits - ones
	if hostBits >= 63 {
		return ^uint64(0)
	}
	return uint64(1) << uint(hostBits)
}

func randomUint64Below(rng *rand.Rand, limit uint64) uint64 {
	if limit <= 1 {
		return 0
	}
	threshold := -limit % limit
	for {
		v := rng.Uint64()
		if v >= threshold {
			return v % limit
		}
	}
}

func builtinRangesV4(kind provider.Kind) string {
	switch provider.Normalize(string(kind)) {
	case provider.CloudFront:
		return builtinCloudFrontV4
	case provider.Gcore:
		return builtinGcoreV4
	case provider.Fastly:
		return builtinFastlyV4
	default:
		return builtinV4
	}
}

func builtinRangesV6(kind provider.Kind) string {
	switch provider.Normalize(string(kind)) {
	case provider.CloudFront:
		return builtinCloudFrontV6
	default:
		return builtinV6
	}
}

func randomFromNet(n *net.IPNet, rng *rand.Rand) net.IP {
	ip4 := n.IP.To4()
	if ip4 != nil {
		base := binary.BigEndian.Uint32(ip4)
		mask := binary.BigEndian.Uint32([]byte(n.Mask))
		size := ^mask
		offset := rng.Uint32() & size
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, base|offset)
		return ip
	}
	// IPv6: randomise the host portion byte-by-byte
	ip := make(net.IP, len(n.IP))
	copy(ip, n.IP)
	for i, b := range n.Mask {
		host := byte(rng.Intn(256)) &^ b
		ip[i] = n.IP[i] | host
	}
	return ip
}

func cloneIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func netsToStrings(nets []*net.IPNet) []string {
	s := make([]string, len(nets))
	for i, n := range nets {
		s[i] = n.String()
	}
	return s
}
