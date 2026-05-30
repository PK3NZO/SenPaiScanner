package provider

import (
	"net/http"
	"strings"
)

type Kind string

const (
	Cloudflare Kind = "cloudflare"
	CloudFront Kind = "cloudfront"
)

func Normalize(raw string) Kind {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", string(Cloudflare), "cf":
		return Cloudflare
	case string(CloudFront), "aws", "amazon", "amazon-cloudfront":
		return CloudFront
	default:
		return Cloudflare
	}
}

func All() []Kind {
	return []Kind{Cloudflare, CloudFront}
}

func DisplayName(kind Kind) string {
	switch Normalize(string(kind)) {
	case CloudFront:
		return "CloudFront"
	default:
		return "Cloudflare"
	}
}

func SupportsColo(kind Kind) bool {
	return Normalize(string(kind)) == Cloudflare
}

func DefaultHTTPHost(kind Kind) string {
	switch Normalize(string(kind)) {
	case CloudFront:
		return "d7uri8nf7uskq.cloudfront.net"
	default:
		return "speed.cloudflare.com"
	}
}

func DefaultHTTPPath(kind Kind) string {
	switch Normalize(string(kind)) {
	case CloudFront:
		return "/tools/list-cloudfront-ips"
	default:
		return "/cdn-cgi/trace"
	}
}

func RotationHosts(kind Kind) []string {
	switch Normalize(string(kind)) {
	case CloudFront:
		return []string{DefaultHTTPHost(CloudFront)}
	default:
		return []string{
			"speed.cloudflare.com",
			"www.cloudflare.com",
			"cloudflare.com",
			"1.1.1.1.cdn.cloudflare.net",
			"blog.cloudflare.com",
		}
	}
}

func SupportsDownload(kind Kind) bool {
	return Normalize(string(kind)) == Cloudflare
}

func SupportsWebSocketHold(kind Kind) bool {
	return Normalize(string(kind)) == Cloudflare
}

func VerifyHTTP(kind Kind, status int, headers http.Header, body string) (verified bool, colo string) {
	switch Normalize(string(kind)) {
	case CloudFront:
		if status < 200 || status >= 400 {
			return false, ""
		}
		if !strings.Contains(body, "CLOUDFRONT_GLOBAL_IP_LIST") {
			return false, ""
		}
		return true, parseCloudFrontPoP(headers.Get("X-Amz-Cf-Pop"))
	default:
		colo = parseCloudflarePoP(headers.Get("CF-Ray"), body)
		if status < 200 || status >= 400 || colo == "" {
			return false, colo
		}
		return true, colo
	}
}

func DownloadURL(kind Kind, scheme string, bytes int64) string {
	switch Normalize(string(kind)) {
	case CloudFront:
		return ""
	default:
		return scheme + "://speed.cloudflare.com/__down?bytes=" + itoa(bytes)
	}
}

func parseCloudflarePoP(ray, body string) string {
	if colo := parseCloudflareRay(ray); colo != "" {
		return colo
	}
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "colo=") {
			return strings.TrimPrefix(line, "colo=")
		}
	}
	return ""
}

func parseCloudflareRay(ray string) string {
	parts := strings.Split(ray, "-")
	if len(parts) < 2 {
		return ""
	}
	colo := strings.TrimSpace(parts[len(parts)-1])
	if len(colo) < 3 {
		return ""
	}
	return strings.ToUpper(colo[:3])
}

func parseCloudFrontPoP(pop string) string {
	pop = strings.TrimSpace(pop)
	if pop == "" {
		return ""
	}
	if idx := strings.Index(pop, "-"); idx > 0 {
		return strings.ToUpper(pop[:idx])
	}
	return strings.ToUpper(pop)
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	sign := ""
	if v < 0 {
		sign = "-"
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return sign + string(buf[i:])
}
