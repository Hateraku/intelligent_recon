package subdomain

import "net"

// Lookup resolves a domain to its IP addresses
func Lookup(target string) ([]string, error) {
	ips, err := net.LookupHost(target)
	if err != nil {
		return nil, err
	}
	return ips, nil
}
