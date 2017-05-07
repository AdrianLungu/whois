package whois

import (
	"fmt"
)

type pirAdapter struct {
	defaultAdapter
}

func (a *pirAdapter) Prepare(req *Request) error {
	if req.URL != "" {
		return ErrURLNotSupported
	}
	req.Body = []byte(fmt.Sprintf("%s\r\n", req.Query))
	return nil
}

func init() {
	BindAdapter(
		&pirAdapter{},
		"whois.pir.org",
	)
}
