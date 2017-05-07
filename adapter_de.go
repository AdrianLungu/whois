package whois

import (
	"fmt"
)

type deAdapter struct {
	defaultAdapter
}

func (a *deAdapter) Prepare(req *Request) error {
	a.defaultAdapter.Prepare(req)
	req.Body = []byte(fmt.Sprintf("-T dn,ace %s\r\n", req.Query)) // http://www.denic.de/en/domains/whois-service.html
	return nil
}

func (a *deAdapter) Parse(res *Response) (*Record, error) {
	err := errorString{"Parser not implemented for adapter"}
	r := Record{}

	return &r, &err
}

func init() {
	BindAdapter(
		&deAdapter{},
		"whois.denic.de",
	)
}
