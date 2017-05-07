package whois

import (
	"fmt"
)

type frAdapter struct {
	defaultAdapter
}

func (a *frAdapter) Prepare(req *Request) error {
	if req.URL != "" {
		return ErrURLNotSupported
	}
	req.Body = []byte(fmt.Sprintf("%s\r\n", req.Query))
	return nil
}

func (a *frAdapter) parseContact(str string) *Contact {
	c := new(Contact)

	c.ID = regex(`(?m)^nic-hdl:(.*)`, str)[0]
	c.Name = regex(`(?m)^contact:(.*)`, str)[0]
	c.Address = regex(`(?m)^address:(.*)`, str)
	c.Country = regex(`(?m)^country:(.*)`, str)[0]
	c.Phone = regex(`(?m)^phone:(.*)`, str)[0]
	c.Fax = regex(`(?m)^fax-no:(.*)`, str)[0]
	c.Email = regex(`(?m)^e-mail:(.*)`, str)[0]

	return c
}

func (a *frAdapter) Parse(res *Response) (r *Record, err error) {
	//err := errorString{"Parser not implemented for adapter"}
	str := res.String()
	r = new(Record)

	r.Whois = res.Host

	var domainStr = regex(`(?msU)[\r\n]{2}(^domain:.*source:.*)[\r\n]+`, str)[0]
	r.Registrar = regex(`(?sU)registrar:([^\r\n]*)?[\n\r]+`, domainStr)[0]
	r.LastUpdate = regex(`(?sU)last-update:([^\r\n]*)?[\n\r]+`, domainStr)[0]
	r.Creation = regex(`(?sU)created:([^\r\n]*)?[\n\r]+`, domainStr)[0]
	r.Expire = regex(`(?sU)Expiry Date:([^\r\n]*)?[\n\r]+`, domainStr)[0]

	var nameserverStr = regex(`(?msU)[\r\n]{2}^ns-list:(.*source:.*)[\r\n]+`, str)[0]
	r.NameServers = regex(`(?sUm)^nserver:(.*)[\[\n\r]`, nameserverStr)
	//var registrar = regex(`(?msU)^[\r\n]{2}registrar:(.*source:.*)[\r\n]+`, str)[0]
	var contactStrs = regex(`(?msU)^(nic-hdl:.*source:.*)[\r\n]+`, str)
	for _, c := range contactStrs {
		var roleStr string
		contact := a.parseContact(c)
		role := regex(fmt.Sprintf(`(?m)^([a-zA-Z]+)-c:.*%s+`, contact.ID), domainStr)[0]
		if role == "holder" {
			roleStr = "owner"
		} else {
			roleStr = role
		}
		contact.Role = roleStr
		r.Contacts = append(r.Contacts, contact)
	}

	return r, err
}

func init() {
	BindAdapter(
		&frAdapter{},
		"whois.nic.fr",
	)
}
