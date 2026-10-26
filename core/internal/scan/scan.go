// Package scan implements SentryBench's check framework: a small plugin
// interface (Check) plus a set of built-in, passive checks that look at
// already-captured request/response pairs for common API security
// footguns — missing security headers, permissive CORS, verbose error
// disclosure, sensitive data in URLs, weak cookie flags, a JWT with
// alg=none, and version-disclosure banners.
//
// Every check here is PASSIVE: it only reads headers/bodies that were
// already captured or returned by a request the user chose to send. None
// of them send extra probe requests, fuzz input, or attempt to exploit
// anything — that keeps the suite safe to run against any target the user
// is already authorized to be talking to. Active checks (e.g. confirming
// an IDOR by trying a second identity's ID) belong in a separate,
// explicitly-invoked package once the identity-matrix UI exists, not here.
package scan

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sentrybench/core/internal/jwtutil"
	"github.com/sentrybench/core/internal/models"
)

// Subject is the normalized request/response pair every check runs against,
// whether it came from captured traffic or a replayed saved request.
type Subject struct {
	Method          string
	URL             string
	RequestHeaders  map[string]string
	RequestBody     string
	ResponseStatus  int
	ResponseHeaders map[string]string
	ResponseBody    string
}

// Check is the plugin interface. Implement this and append to Registry to
// add a new passive check.
type Check interface {
	ID() string
	Run(s Subject) []models.Finding
}

// Registry is the active set of built-in checks. Order doesn't matter;
// Run calls every check for every subject.
var Registry = []Check{
	missingSecurityHeadersCheck{},
	permissiveCORSCheck{},
	verboseErrorCheck{},
	sensitiveDataInURLCheck{},
	insecureCookieCheck{},
	jwtAlgNoneCheck{},
	serverVersionDisclosureCheck{},
}

// Run executes every registered check against every subject and returns
// the combined findings (with WorkspaceID/ScanID/CreatedAt left for the
// caller to fill in — this package doesn't know about storage).
func Run(subjects []Subject) []models.Finding {
	var all []models.Finding
	for _, subj := range subjects {
		for _, check := range Registry {
			all = append(all, check.Run(subj)...)
		}
	}
	return all
}

func finding(checkID, title, severity, description, evidence, method, url, remediation string) models.Finding {
	return models.Finding{
		CheckID:     checkID,
		Title:       title,
		Severity:    severity,
		Description: description,
		Evidence:    evidence,
		Method:      method,
		URL:         url,
		Remediation: remediation,
	}
}

// --- missing-security-headers ------------------------------------------------

type missingSecurityHeadersCheck struct{}

func (missingSecurityHeadersCheck) ID() string { return "missing-security-headers" }

func (c missingSecurityHeadersCheck) Run(s Subject) []models.Finding {
	if s.ResponseStatus == 0 {
		return nil
	}
	required := []string{"Strict-Transport-Security", "X-Content-Type-Options", "Content-Security-Policy"}
	var missing []string
	for _, h := range required {
		if !headerPresent(s.ResponseHeaders, h) {
			missing = append(missing, h)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return []models.Finding{finding(
		c.ID(),
		"Missing recommended security headers",
		models.SeverityLow,
		"The response did not include one or more commonly recommended security headers.",
		strings.Join(missing, ", "),
		s.Method, s.URL,
		"Add the missing headers at the edge or in the application: Strict-Transport-Security, X-Content-Type-Options: nosniff, and a Content-Security-Policy appropriate to the app.",
	)}
}

// --- permissive-cors ----------------------------------------------------------

type permissiveCORSCheck struct{}

func (permissiveCORSCheck) ID() string { return "permissive-cors" }

func (c permissiveCORSCheck) Run(s Subject) []models.Finding {
	origin := headerValue(s.ResponseHeaders, "Access-Control-Allow-Origin")
	creds := headerValue(s.ResponseHeaders, "Access-Control-Allow-Credentials")
	if origin == "" {
		return nil
	}
	if origin == "*" && strings.EqualFold(creds, "true") {
		return []models.Finding{finding(
			c.ID(),
			"Wildcard CORS origin combined with credentials",
			models.SeverityHigh,
			"The response allows any origin (Access-Control-Allow-Origin: *) while also allowing credentials — browsers normally block this combination, but some clients and older browsers may not, and it signals a misconfiguration.",
			fmt.Sprintf("Access-Control-Allow-Origin: %s; Access-Control-Allow-Credentials: %s", origin, creds),
			s.Method, s.URL,
			"Reflect a specific, validated origin instead of \"*\" whenever Access-Control-Allow-Credentials is true.",
		)}
	}
	if origin == "*" {
		return []models.Finding{finding(
			c.ID(),
			"Wildcard CORS origin",
			models.SeverityInfo,
			"The response allows any origin to read it via CORS. This is fine for public, unauthenticated APIs but worth confirming is intentional.",
			"Access-Control-Allow-Origin: *",
			s.Method, s.URL,
			"Scope Access-Control-Allow-Origin to the specific origins that should be able to call this endpoint, if it returns anything non-public.",
		)}
	}
	return nil
}

// --- verbose-error-disclosure --------------------------------------------------

type verboseErrorCheck struct{}

func (verboseErrorCheck) ID() string { return "verbose-error-disclosure" }

var errorMarkers = []string{
	"Traceback (most recent call last)",
	"Exception in thread",
	"at java.",
	"at System.",
	"Microsoft .NET Framework",
	"Fatal error:",
	"Warning: mysql_",
	"ORA-01",
	"org.springframework",
	"django.core",
	"Unhandled exception",
	"stack trace",
}

func (c verboseErrorCheck) Run(s Subject) []models.Finding {
	if s.ResponseStatus < 500 {
		return nil
	}
	body := s.ResponseBody
	for _, marker := range errorMarkers {
		if strings.Contains(body, marker) {
			return []models.Finding{finding(
				c.ID(),
				"Verbose error response may leak internals",
				models.SeverityMedium,
				"A server error response contains what looks like a stack trace or framework debug output, which can reveal internal paths, library versions, or logic.",
				truncate(snippetAround(body, marker, 80), 300),
				s.Method, s.URL,
				"Disable debug/verbose error pages in production; return a generic error body and log the detail server-side instead.",
			)}
		}
	}
	return nil
}

// --- sensitive-data-in-url -----------------------------------------------------

type sensitiveDataInURLCheck struct{}

func (sensitiveDataInURLCheck) ID() string { return "sensitive-data-in-url" }

var sensitiveParamPattern = regexp.MustCompile(`(?i)[?&](password|passwd|token|api[_-]?key|secret|access[_-]?token|session[_-]?id)=`)

func (c sensitiveDataInURLCheck) Run(s Subject) []models.Finding {
	match := sensitiveParamPattern.FindString(s.URL)
	if match == "" {
		return nil
	}
	return []models.Finding{finding(
		c.ID(),
		"Sensitive-looking parameter in URL",
		models.SeverityMedium,
		"The request URL appears to carry a credential or token as a query parameter. URLs are commonly logged by proxies, browsers, and servers, so secrets here can leak via logs, browser history, or the Referer header.",
		match,
		s.Method, s.URL,
		"Move credentials/tokens into the request body or an Authorization header instead of the URL.",
	)}
}

// --- insecure-cookie-flags -----------------------------------------------------

type insecureCookieCheck struct{}

func (insecureCookieCheck) ID() string { return "insecure-cookie-flags" }

func (c insecureCookieCheck) Run(s Subject) []models.Finding {
	setCookie := headerValue(s.ResponseHeaders, "Set-Cookie")
	if setCookie == "" {
		return nil
	}
	var missing []string
	lower := strings.ToLower(setCookie)
	if !strings.Contains(lower, "secure") {
		missing = append(missing, "Secure")
	}
	if !strings.Contains(lower, "httponly") {
		missing = append(missing, "HttpOnly")
	}
	if !strings.Contains(lower, "samesite") {
		missing = append(missing, "SameSite")
	}
	if len(missing) == 0 {
		return nil
	}
	return []models.Finding{finding(
		c.ID(),
		"Cookie missing recommended flags",
		models.SeverityMedium,
		"A Set-Cookie header is missing one or more flags that reduce exposure to XSS/CSRF and network interception.",
		fmt.Sprintf("Set-Cookie present, missing: %s", strings.Join(missing, ", ")),
		s.Method, s.URL,
		"Set Secure, HttpOnly, and an appropriate SameSite value on session/auth cookies.",
	)}
}

// --- jwt-alg-none ---------------------------------------------------------------

type jwtAlgNoneCheck struct{}

func (jwtAlgNoneCheck) ID() string { return "jwt-alg-none" }

var jwtLikePattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)

func (c jwtAlgNoneCheck) Run(s Subject) []models.Finding {
	candidates := jwtLikePattern.FindAllString(s.ResponseBody+" "+headerValue(s.RequestHeaders, "Authorization"), -1)
	for _, token := range candidates {
		decoded, err := jwtutil.Decode(token)
		if err != nil {
			continue
		}
		if strings.EqualFold(decoded.Algorithm, "none") {
			return []models.Finding{finding(
				c.ID(),
				"JWT with alg=none observed",
				models.SeverityCritical,
				"A token using the \"none\" algorithm was seen in traffic. If the server accepts alg=none tokens, authentication can be bypassed entirely by crafting an unsigned token.",
				truncate(token, 120),
				s.Method, s.URL,
				"Reject alg=none at the verification layer; pin the expected algorithm(s) explicitly rather than trusting the token's own header.",
			)}
		}
	}
	return nil
}

// --- server-version-disclosure --------------------------------------------------

type serverVersionDisclosureCheck struct{}

func (serverVersionDisclosureCheck) ID() string { return "server-version-disclosure" }

var versionPattern = regexp.MustCompile(`\d+\.\d+(\.\d+)?`)

func (c serverVersionDisclosureCheck) Run(s Subject) []models.Finding {
	for _, h := range []string{"Server", "X-Powered-By"} {
		v := headerValue(s.ResponseHeaders, h)
		if v != "" && versionPattern.MatchString(v) {
			return []models.Finding{finding(
				c.ID(),
				"Server software version disclosed",
				models.SeverityInfo,
				fmt.Sprintf("The %s header reveals a specific software version, which can help an attacker match known vulnerabilities.", h),
				fmt.Sprintf("%s: %s", h, v),
				s.Method, s.URL,
				fmt.Sprintf("Suppress or genericize the %s header at the proxy/load balancer.", h),
			)}
		}
	}
	return nil
}

// --- helpers --------------------------------------------------------------------

func headerPresent(headers map[string]string, name string) bool {
	return headerValue(headers, name) != ""
}

func headerValue(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func snippetAround(body, marker string, context int) string {
	idx := strings.Index(body, marker)
	if idx == -1 {
		return marker
	}
	start := idx - context
	if start < 0 {
		start = 0
	}
	end := idx + len(marker) + context
	if end > len(body) {
		end = len(body)
	}
	return body[start:end]
}
