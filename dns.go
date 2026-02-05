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

// lookupIPv4 resolves a DNS name and returns only IPv4 addresses
func lookupIPv4(hostname string) ([]net.IP, error) {
	ips, err := lookupIP(hostname)
	if err != nil {
		return nil, err
	}

	var ipv4s []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			ipv4s = append(ipv4s, ip)
		}
	}
	return ipv4s, nil
}

// lookupIPv6 resolves a DNS name and returns only IPv6 addresses
func lookupIPv6(hostname string) ([]net.IP, error) {
	ips, err := lookupIP(hostname)
	if err != nil {
		return nil, err
	}

	var ipv6s []net.IP
	for _, ip := range ips {
		if ip.To4() == nil {
			ipv6s = append(ipv6s, ip)
		}
	}
	return ipv6s, nil
}
