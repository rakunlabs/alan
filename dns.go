package alan

import (
	"fmt"
	"net"
)

// lookupIP resolves a DNS name and returns its IP addresses
func lookupIP(hostname string) ([]net.IP, error) {
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup %s: %w", hostname, err)
	}
	return ips, nil
}
