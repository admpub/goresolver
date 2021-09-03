package main

import (
	"fmt"
	"os"

	"github.com/admpub/goresolver"
	"github.com/miekg/dns"
)

func main() {

	if len(os.Args) < 2 {
		fmt.Printf("Usage: mxlookup <hostname>\n")
		os.Exit(0)
	}
	hostname := os.Args[1]

	resolver, err := goresolver.NewResolver("/etc/resolv.conf")

	if err != nil {
		fmt.Printf("Cannot initialize the local resolver: %s\n", err)
		os.Exit(1)
	}

	result, err := resolver.StrictNSQuery(dns.Fqdn(hostname), dns.TypeMX)

	if err != nil {
		fmt.Printf("Validation failed: %s\n", err)
		os.Exit(1)
	}

	fmt.Println("DNSSEC validation successful\n", result)
}
