package whois

import (
	"fmt"
	"strconv"
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

func parseContact(str string, contactStr string, contactType string) *Contact {
	c := new(Contact)
	c.Type = contactType

	c.ID = regex(fmt.Sprintf(`(?sU)Registry[\s\t]+%s[\s\t]+ID:([^\r\n]*)?[\n\r]+`, contactStr), str)[0]
	c.Name = regex(fmt.Sprintf(`(?sU)%s[\s\t]+Name:([^\r\n]*)?[\n\r]+`, contactStr), str)[0]
	c.Organization = regex(fmt.Sprintf(`(?sU)%s[\s\t]+Organization:([^\r\n]*)?[\n\r]+`, contactStr), str)[0]
	c.Street = regex(fmt.Sprintf(`(?sU)%s[\s\t]+Street:([^\r\n]*)?[\n\r]+`, contactStr), str)
	c.City = regex(fmt.Sprintf(`(?sU)%s[\s\t]+City:([^\r\n]*)?[\n\r]+`, contactStr), str)[0]
	c.StateProvince = regex(fmt.Sprintf(`(?sU)%s[\s\t]+State/Province:([^\r\n]*)?[\n\r]+`, contactStr), str)[0]
	c.PostalCode = regex(fmt.Sprintf(`(?sU)%s[\s\t]+Postal[\s\t]+Code:([^\r\n]*)?[\n\r]+`, contactStr), str)[0]
	c.Country = regex(fmt.Sprintf(`(?sU)%s[\s\t]+Country:([^\r\n]*)?[\n\r]+`, contactStr), str)[0]
	c.Phone = regex(fmt.Sprintf(`(?sU)%s[\s\t]+Phone:([^\r\n]*)?[\n\r]+`, contactStr), str)[0]
	c.PhoneExt = regex(fmt.Sprintf(`(?sU)%s[\s\t]+Phone[\s\t]+Ext:([^\r\n]*)?[\n\r]+`, contactStr), str)[0]
	c.Fax = regex(fmt.Sprintf(`(?sU)%s[\s\t]+Fax:([^\r\n]*)?[\n\r]+`, contactStr), str)[0]
	c.FaxExt = regex(fmt.Sprintf(`(?sU)%s[\s\t]+Fax[\s\t]+Ext:([^\r\n]*)?[\n\r]+`, contactStr), str)[0]
	c.Email = regex(fmt.Sprintf(`(?sU)%s[\s\t]+Email:([^\r\n]*)?[\n\r]+`, contactStr), str)[0]

	return c
}

func (a *pirAdapter) Parse(res *Response) (r *Record, err error) {
	//err := errorString{}
	str := res.String()
	r = new(Record)

	r.Registrar = regex(`(?sU)Registrar:([^\r\n]*)?[\n\r]+`, str)[0]
	r.SponsoringRegistrarID, _ = strconv.Atoi(regex(`(?sU)Registrar IANA ID:([^\r\n]*)?[\n\r]+`, str)[0])
	r.Whois = regex(`(?sU)Registrar WHOIS Server:([^\r\n]*)?[\n\r]+`, str)[0]
	r.ReferralURL = regex(`(?sU)Registrar URL:([^\r\n]*)?[\n\r]+`, str)[0]
	r.LastUpdate = regex(`(?sU)Updated Date:([^\r\n]*)?[\n\r]+`, str)[0]
	r.Creation = regex(`(?sU)Creation Date:([^\r\n]*)?[\n\r]+`, str)[0]
	r.Expire = regex(`(?sU)Registry Expiry Date:([^\r\n]*)?[\n\r]+`, str)[0]
	r.DNSSEC = regex(`(?sU)DNSSEC:([^\r\n]*)?[\n\r]+`, str)[0]

	r.NameServers = regex(`(?sU)Name Server:([^\r\n]*)?[\n\r]+`, str)

	r.Status = regex(`(?sU)Domain Status:[\s\t]+([^\r\n]*)?\s+`, str)
	r.Contacts = append(r.Contacts, parseContact(str, "Registrant", "owner"))
	r.Contacts = append(r.Contacts, parseContact(str, "Admin", "tech"))
	r.Contacts = append(r.Contacts, parseContact(str, "Tech", "admin"))

	return r, err
}

func init() {
	BindAdapter(
		&pirAdapter{},
		"whois.pir.org",
	)
}
