package whois

import (
	"fmt"
)

type ioAdapter struct {
	defaultAdapter
}

func (a *ioAdapter) Prepare(req *Request) error {
	if req.URL != "" {
		return ErrURLNotSupported
	}
	req.Body = []byte(fmt.Sprintf("%s\r\n", req.Query))
	return nil
}

func (a *ioAdapter) Parse(res *Response) (*Record, error) {
	err := errorString{"Parser not implemented for adapter"}
	r := Record{}

	return &r, &err
}

func init() {
	BindAdapter(
		&deAdapter{},
		"whois.nic.io",
	)
}
