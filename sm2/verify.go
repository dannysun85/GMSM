package sm2

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"
)

type InvalidReason int

const (
	NotAuthorizedToSign InvalidReason = iota
	Expired
	CANotAuthorizedForThisName
	TooManyIntermediates
	IncompatibleUsage
	NameMismatch
)

type CertificateInvalidError struct {
	Cert   *Certificate
	Reason InvalidReason
}

func (e CertificateInvalidError) Error() string {
	switch e.Reason {
	case NotAuthorizedToSign:
		return "x509: certificate is not authorized to sign other certificates"
	case Expired:
		return "x509: certificate has expired or is not yet valid"
	case CANotAuthorizedForThisName:
		return "x509: a root or intermediate certificate is not authorized to sign in this domain"
	case TooManyIntermediates:
		return "x509: too many intermediates for path length constraint"
	case IncompatibleUsage:
		return "x509: certificate specifies an incompatible key usage"
	case NameMismatch:
		return "x509: issuer name does not match subject from issuing certificate"
	}
	return "x509: unknown error"
}

type HostnameError struct {
	Certificate *Certificate
	Host        string
}

func (h HostnameError) Error() string {
	c := h.Certificate

	var valid string
	if ip := net.ParseIP(h.Host); ip != nil {
		if len(c.IPAddresses) == 0 {
			return "x509: cannot validate certificate for " + h.Host + " because it doesn't contain any IP SANs"
		}
		for _, san := range c.IPAddresses {
			if len(valid) > 0 {
				valid += ", "
			}
			valid += san.String()
		}
	} else {
		if len(c.DNSNames) > 0 {
			valid = strings.Join(c.DNSNames, ", ")
		} else {
			valid = c.Subject.CommonName
		}
	}

	if len(valid) == 0 {
		return "x509: certificate is not valid for any names, but wanted to match " + h.Host
	}
	return "x509: certificate is valid for " + valid + ", not " + h.Host
}

type UnknownAuthorityError struct {
	Cert *Certificate
	hintErr error
	hintCert *Certificate
}

func (e UnknownAuthorityError) Error() string {
	s := "x509: certificate signed by unknown authority"
	if e.hintErr != nil {
		certName := e.hintCert.Subject.CommonName
		if len(certName) == 0 {
			if len(e.hintCert.Subject.Organization) > 0 {
				certName = e.hintCert.Subject.Organization[0]
			} else {
				certName = "serial:" + e.hintCert.SerialNumber.String()
			}
		}
		s += fmt.Sprintf(" (possibly because of %q while trying to verify candidate authority certificate %q)", e.hintErr, certName)
	}
	return s
}

type SystemRootsError struct {
	Err error
}

func (se SystemRootsError) Error() string {
	msg := "x509: failed to load system roots and no roots provided"
	if se.Err != nil {
		return msg + "; " + se.Err.Error()
	}
	return msg
}

var errNotParsed = errors.New("x509: missing ASN.1 contents; use ParseCertificate")


type VerifyOptions struct {
	DNSName       string
	Intermediates *CertPool
	Roots         *CertPool 
	CurrentTime   time.Time 
	KeyUsages []ExtKeyUsage
}

const (
	leafCertificate = iota
	intermediateCertificate
	rootCertificate
)

func matchNameConstraint(domain, constraint string) bool {
	if len(constraint) == 0 {
		return true
	}

	if len(domain) < len(constraint) {
		return false
	}

	prefixLen := len(domain) - len(constraint)
	if !strings.EqualFold(domain[prefixLen:], constraint) {
		return false
	}

	if prefixLen == 0 {
		return true
	}

	isSubdomain := domain[prefixLen-1] == '.'
	constraintHasLeadingDot := constraint[0] == '.'
	return isSubdomain != constraintHasLeadingDot
}

func (c *Certificate) isValid(certType int, currentChain []*Certificate, opts *VerifyOptions) error {
	if len(currentChain) > 0 {
		child := currentChain[len(currentChain)-1]
		if !bytes.Equal(child.RawIssuer, c.RawSubject) {
			return CertificateInvalidError{c, NameMismatch}
		}
	}
	now := opts.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}
	if now.Before(c.NotBefore) || now.After(c.NotAfter) {
		return CertificateInvalidError{c, Expired}
	}
	if len(c.PermittedDNSDomains) > 0 {
		ok := false
		for _, constraint := range c.PermittedDNSDomains {
			ok = matchNameConstraint(opts.DNSName, constraint)
			if ok {
				break
			}
		}

		if !ok {
			return CertificateInvalidError{c, CANotAuthorizedForThisName}
		}
	}

	

	if certType == intermediateCertificate && (!c.BasicConstraintsValid || !c.IsCA) {
		return CertificateInvalidError{c, NotAuthorizedToSign}
	}

	if c.BasicConstraintsValid && c.MaxPathLen >= 0 {
		numIntermediates := len(currentChain) - 1
		if numIntermediates > c.MaxPathLen {
			return CertificateInvalidError{c, TooManyIntermediates}
		}
	}

	return nil
}

func (c *Certificate) Verify(opts VerifyOptions) (chains [][]*Certificate, err error) {
	if len(c.Raw) == 0 {
		return nil, errNotParsed
	}
	if opts.Intermediates != nil {
		for _, intermediate := range opts.Intermediates.certs {
			if len(intermediate.Raw) == 0 {
				return nil, errNotParsed
			}
		}
	}

	if opts.Roots == nil && runtime.GOOS == "windows" {
		return c.systemVerify(&opts)
	}

	if len(c.UnhandledCriticalExtensions) > 0 {
		return nil, UnhandledCriticalExtension{}
	}

	if opts.Roots == nil {
		opts.Roots = systemRootsPool()
		if opts.Roots == nil {
			return nil, SystemRootsError{systemRootsErr}
		}
	}

	err = c.isValid(leafCertificate, nil, &opts)
	if err != nil {
		return
	}

	if len(opts.DNSName) > 0 {
		err = c.VerifyHostname(opts.DNSName)
		if err != nil {
			return
		}
	}

	var candidateChains [][]*Certificate
	if opts.Roots.contains(c) {
		candidateChains = append(candidateChains, []*Certificate{c})
	} else {
		if candidateChains, err = c.buildChains(make(map[int][][]*Certificate), []*Certificate{c}, &opts); err != nil {
			return nil, err
		}
	}

	keyUsages := opts.KeyUsages
	if len(keyUsages) == 0 {
		keyUsages = []ExtKeyUsage{ExtKeyUsageServerAuth}
	}

	for _, usage := range keyUsages {
		if usage == ExtKeyUsageAny {
			chains = candidateChains
			return
		}
	}

	for _, candidate := range candidateChains {
		if checkChainForKeyUsage(candidate, keyUsages) {
			chains = append(chains, candidate)
		}
	}

	if len(chains) == 0 {
		err = CertificateInvalidError{c, IncompatibleUsage}
	}

	return
}

func appendToFreshChain(chain []*Certificate, cert *Certificate) []*Certificate {
	n := make([]*Certificate, len(chain)+1)
	copy(n, chain)
	n[len(chain)] = cert
	return n
}

func (c *Certificate) buildChains(cache map[int][][]*Certificate, currentChain []*Certificate, opts *VerifyOptions) (chains [][]*Certificate, err error) {
	possibleRoots, failedRoot, rootErr := opts.Roots.findVerifiedParents(c)
nextRoot:
	for _, rootNum := range possibleRoots {
		root := opts.Roots.certs[rootNum]

		for _, cert := range currentChain {
			if cert.Equal(root) {
				continue nextRoot
			}
		}

		err = root.isValid(rootCertificate, currentChain, opts)
		if err != nil {
			continue
		}
		chains = append(chains, appendToFreshChain(currentChain, root))
	}

	possibleIntermediates, failedIntermediate, intermediateErr := opts.Intermediates.findVerifiedParents(c)
nextIntermediate:
	for _, intermediateNum := range possibleIntermediates {
		intermediate := opts.Intermediates.certs[intermediateNum]
		for _, cert := range currentChain {
			if cert.Equal(intermediate) {
				continue nextIntermediate
			}
		}
		err = intermediate.isValid(intermediateCertificate, currentChain, opts)
		if err != nil {
			continue
		}
		var childChains [][]*Certificate
		childChains, ok := cache[intermediateNum]
		if !ok {
			childChains, err = intermediate.buildChains(cache, appendToFreshChain(currentChain, intermediate), opts)
			cache[intermediateNum] = childChains
		}
		chains = append(chains, childChains...)
	}

	if len(chains) > 0 {
		err = nil
	}

	if len(chains) == 0 && err == nil {
		hintErr := rootErr
		hintCert := failedRoot
		if hintErr == nil {
			hintErr = intermediateErr
			hintCert = failedIntermediate
		}
		err = UnknownAuthorityError{c, hintErr, hintCert}
	}

	return
}

func matchHostnames(pattern, host string) bool {
	host = strings.TrimSuffix(host, ".")
	pattern = strings.TrimSuffix(pattern, ".")

	if len(pattern) == 0 || len(host) == 0 {
		return false
	}

	patternParts := strings.Split(pattern, ".")
	hostParts := strings.Split(host, ".")

	if len(patternParts) != len(hostParts) {
		return false
	}

	for i, patternPart := range patternParts {
		if i == 0 && patternPart == "*" {
			continue
		}
		if patternPart != hostParts[i] {
			return false
		}
	}

	return true
}

func toLowerCaseASCII(in string) string {
	isAlreadyLowerCase := true
	for _, c := range in {
		if c == utf8.RuneError {
			isAlreadyLowerCase = false
			break
		}
		if 'A' <= c && c <= 'Z' {
			isAlreadyLowerCase = false
			break
		}
	}

	if isAlreadyLowerCase {
		return in
	}

	out := []byte(in)
	for i, c := range out {
		if 'A' <= c && c <= 'Z' {
			out[i] += 'a' - 'A'
		}
	}
	return string(out)
}

func (c *Certificate) VerifyHostname(h string) error {
	candidateIP := h
	if len(h) >= 3 && h[0] == '[' && h[len(h)-1] == ']' {
		candidateIP = h[1 : len(h)-1]
	}
	if ip := net.ParseIP(candidateIP); ip != nil {
		for _, candidate := range c.IPAddresses {
			if ip.Equal(candidate) {
				return nil
			}
		}
		return HostnameError{c, candidateIP}
	}

	lowered := toLowerCaseASCII(h)

	if len(c.DNSNames) > 0 {
		for _, match := range c.DNSNames {
			if matchHostnames(toLowerCaseASCII(match), lowered) {
				return nil
			}
		}
	} else if matchHostnames(toLowerCaseASCII(c.Subject.CommonName), lowered) {
		return nil
	}

	return HostnameError{c, h}
}

func checkChainForKeyUsage(chain []*Certificate, keyUsages []ExtKeyUsage) bool {
	usages := make([]ExtKeyUsage, len(keyUsages))
	copy(usages, keyUsages)

	if len(chain) == 0 {
		return false
	}

	usagesRemaining := len(usages)


NextCert:
	for i := len(chain) - 1; i >= 0; i-- {
		cert := chain[i]
		if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
			continue
		}

		for _, usage := range cert.ExtKeyUsage {
			if usage == ExtKeyUsageAny {
				continue NextCert
			}
		}

		const invalidUsage ExtKeyUsage = -1

	NextRequestedUsage:
		for i, requestedUsage := range usages {
			if requestedUsage == invalidUsage {
				continue
			}

			for _, usage := range cert.ExtKeyUsage {
				if requestedUsage == usage {
					continue NextRequestedUsage
				} else if requestedUsage == ExtKeyUsageServerAuth &&
					(usage == ExtKeyUsageNetscapeServerGatedCrypto ||
						usage == ExtKeyUsageMicrosoftServerGatedCrypto) {
					continue NextRequestedUsage
				}
			}

			usages[i] = invalidUsage
			usagesRemaining--
			if usagesRemaining == 0 {
				return false
			}
		}
	}

	return true
}
