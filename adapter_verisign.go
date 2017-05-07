package whois

import (
	"fmt"
	"strconv"
)

type verisignAdapter struct {
	defaultAdapter
}

func (a *verisignAdapter) Prepare(req *Request) error {
	a.defaultAdapter.Prepare(req)
	req.Body = []byte(fmt.Sprintf("=%s\r\n", req.Query))
	return nil
}

// Parse will only be called if there is no whois server specified
// It's a fallback to get "some" information
func (a *verisignAdapter) Parse(res *Response) (r *Record, err error) {
	//err := errorString{}
	str := res.String()
	r = new(Record)

	r.Registrar = regex(`(?sU)Registrar:([^\r\n]*)?[\n\r]+`, str)[0]
	r.SponsoringRegistrarID, _ = strconv.Atoi(regex(`(?sU)Sponsoring Registrar IANA ID:([^\r\n]*)?[\n\r]+`, str)[0])
	r.Whois = regex(`(?sU)Whois Server:([^\r\n]*)?[\n\r]+`, str)[0]
	r.ReferralURL = regex(`(?sU)Referral URL:([^\r\n]*)?[\n\r]+`, str)[0]
	r.LastUpdate = regex(`(?sU)Updated Date:([^\r\n]*)?[\n\r]+`, str)[0]
	r.Creation = regex(`(?sU)Creation Date:([^\r\n]*)?[\n\r]+`, str)[0]
	r.Expire = regex(`(?sU)Expiration Date:([^\r\n]*)?[\n\r]+`, str)[0]

	r.NameServers = regex(`(?sU)Name Server:([^\r\n]*)?[\n\r]+`, str)

	r.Status = regex(`(?sU)Status:[\s\t]+([^\r\n]*)?\s+`, str)
	r.NameServers = regex(`(?sU)Name Server:[\s\t]+?(.+)?[\n\r]+`, str)

	return r, err
}

func init() {
	BindAdapter(
		&verisignAdapter{},
		"whois.verisign-grs.com",
		"bzwhois.verisign-grs.com",
		"ccwhois.verisign-grs.com",
		"tvwhois.verisign-grs.com",
		"jobswhois.verisign-grs.com",
	)
}
