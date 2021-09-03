package goresolver

import (
	"log"
	"strings"

	"github.com/miekg/dns"
)

type RRSet struct {
	rrSet []dns.RR
	rrSig *dns.RRSIG
}

func queryRRset(qname string, qtype uint16) (*RRSet, error) {

	triesLeft := 2

RETRY:
	r, err := resolver.queryFn(qname, qtype)

	if err != nil {
		if strings.HasSuffix(err.Error(), "i/o timeout") && triesLeft > 0 {
			triesLeft--
			goto RETRY
		}
		log.Printf("cannot lookup %v", err)
		return nil, err
	}

	if r.Rcode == dns.RcodeNameError {
		log.Printf("no such domain %s\n", qname)
		return nil, ErrNoResult
	}

	result := NewSignedRRSet()

	if r.Answer == nil {
		return result, nil
	}

	result.rrSet = make([]dns.RR, 0, len(r.Answer))

	for _, rr := range r.Answer {
		switch t := rr.(type) {
		case *dns.RRSIG:
			result.rrSig = t
		default:
			if rr != nil {
				result.rrSet = append(result.rrSet, rr)
			}
		}
	}
	return result, nil
}

func (sRRset *RRSet) IsSigned() bool {
	return sRRset.rrSig != nil
}

func (sRRset *RRSet) IsEmpty() bool {
	return len(sRRset.rrSet) < 1
}

func (sRRset *RRSet) SignerName() string {
	return sRRset.rrSig.SignerName
}

func NewSignedRRSet() *RRSet {
	return &RRSet{
		rrSet: make([]dns.RR, 0),
	}
}
