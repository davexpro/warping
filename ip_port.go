package main

import (
	"net"
)

// GenerateIPsFromCIDR 从给定的 CIDR 生成所有可能的IPv4地址
func GenerateIPsFromCIDR(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	inc := func(ip net.IP) {
		for j := len(ip) - 1; j >= 0; j-- {
			ip[j]++
			if ip[j] > 0 {
				break
			}
		}
	}

	var ips []string
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		if ip[3] == 0 || ip[3] == 255 {
			continue
		}
		ips = append(ips, ip.String())
	}

	return ips, nil
}

// GenerateProbes 从给定的 ips + port 生成所有对应的组合
func GenerateProbes(ips []string, port int) []*Probe {
	probes := make([]*Probe, 0, len(ips))
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		probes = append(probes, &Probe{ip: &ip, port: port})
	}
	return probes
}
