package whois

import (
	"net/url"
)

type azAdapter struct {
	defaultAdapter
}

func (a *azAdapter) Prepare(req *Request) error {
	values := url.Values{}
	values.Set("lang", "en")
	values.Set("domain", req.Query)
	values.Set("dom", "") // The server concatentates domain+dom, so we can leave dom empty
	req.URL = "http://www.whois.az/cgi-bin/whois.cgi"
	req.Body = []byte(values.Encode())
	return nil
}

func (a *azAdapter) Parse(res *Response) (*Record, error) {
	err := errorString{"Parser not implemented for adapter"}
	r := Record{}

	return &r, &err
}

func init() {
	BindAdapter(
		&azAdapter{},
		"www.whois.az",
		"www.nic.az",
	)
}
