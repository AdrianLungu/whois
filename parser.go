package whois

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

func regex(expression string, str string) []string {
	var retval []string
	re := regexp.MustCompile(expression).FindAllStringSubmatch(str, -1)
	if len(re) > 0 {
		for _, val := range re {
			retval = append(retval, strings.TrimSpace(val[1]))
		}
	} else {
		retval = append(retval, "")
	}

	return retval
}

func parseContact(str string, contactStr string) *Contact {
	c := new(Contact)

	c.ID = regex(fmt.Sprintf(`(?sU)Registry[\s\t]+%s[\s\t]+ID:([^\r\n]*)?[\n\r]+`, contactStr), str)[0]
	c.Name = regex(fmt.Sprintf(`(?sU)%s[\s\t]+Name:([^\r\n]*)?[\n\r]+`, contactStr), str)[0]
	c.Organization = regex(fmt.Sprintf(`(?sU)%s[\s\t]+Organization:([^\r\n]*)?[\n\r]+`, contactStr), str)[0]
	c.Address = regex(fmt.Sprintf(`(?sU)%s[\s\t]+Street:([^\r\n]*)?[\n\r]+`, contactStr), str)

	city := regex(fmt.Sprintf(`(?sU)%s[\s\t]+City:([^\r\n]*)?[\n\r]+`, contactStr), str)[0]
	stateProvince := regex(fmt.Sprintf(`(?sU)%s[\s\t]+State/Province:([^\r\n]*)?[\n\r]+`, contactStr), str)[0]
	postalCode := regex(fmt.Sprintf(`(?sU)%s[\s\t]+Postal[\s\t]+Code:([^\r\n]*)?[\n\r]+`, contactStr), str)[0]
	c.Address = append(c.Address, fmt.Sprintf("%s, %s, %s", city, stateProvince, postalCode))

	c.Country = regex(fmt.Sprintf(`(?sU)%s[\s\t]+Country:([^\r\n]*)?[\n\r]+`, contactStr), str)[0]

	phone := regex(fmt.Sprintf(`(?sU)%s[\s\t]+Phone:([^\r\n]*)?[\n\r]+`, contactStr), str)[0]
	phoneExt := regex(fmt.Sprintf(`(?sU)%s[\s\t]+Phone[\s\t]+Ext:([^\r\n]*)?[\n\r]+`, contactStr), str)[0]
	if phoneExt != "" {
		c.Phone = fmt.Sprintf("%s x%s", phone, phoneExt)
	} else {
		c.Phone = phone
	}

	fax := regex(fmt.Sprintf(`(?sU)%s[\s\t]+Fax:([^\r\n]*)?[\n\r]+`, contactStr), str)[0]
	faxExt := regex(fmt.Sprintf(`(?sU)%s[\s\t]+Fax[\s\t]+Ext:([^\r\n]*)?[\n\r]+`, contactStr), str)[0]
	if faxExt != "" {
		c.Fax = fmt.Sprintf("%s x%s", fax, faxExt)
	} else {
		c.Fax = fax
	}

	c.Email = regex(fmt.Sprintf(`(?sU)%s[\s\t]+Email:([^\r\n]*)?[\n\r]+`, contactStr), str)[0]

	return c
}

func parse(res *Response) (r *Record, err error) {
	//err := errorString{}
	str := res.String()
	r = new(Record)

	r.Registrar = regex(`(?sU)Registrar:([^\r\n]*)?[\n\r]+`, str)[0]
	r.SponsoringRegistrarID, _ = strconv.Atoi(regex(`(?sU)Registr[ary]+ IANA ID:([^\r\n]*)?[\n\r]+`, str)[0])
	//.Whois = regex(`(?Ui)WHOIS Server:([^\r\n]*)?[\n\r]+`, str)[0]
	r.Whois = res.Host
	r.ReferralURL = regex(`(?Ui)Registrar URL:([^\r\n]*)?[\n\r]+`, str)[0]
	r.LastUpdate = regex(`(?Ui)Updated Date:([^\r\n]*)?[\n\r]+`, str)[0]
	r.Creation = regex(`(?Ui)Creation Date:([^\r\n]*)?[\n\r]+`, str)[0]
	registryExpiry := regex(`(?Ui)Registry Expiry Date:([^\r\n]*)?[\n\r]+`, str)[0]
	if registryExpiry == "" {
		r.Expire = regex(`(?Ui)Expiration Date:([^\r\n]*)?[\n\r]+`, str)[0]
	} else {
		r.Expire = registryExpiry
	}

	r.DNSSEC = regex(`(?iU)DNSSEC:([^\r\n]*)?[\n\r]+`, str)[0]

	r.NameServers = regex(`(?sU)Name Server:([^\r\n]*)?[\n\r]+`, str)

	r.Status = regex(`(?sU)Domain Status:[\s\t]+([^\r\n]*)?\s+`, str)

	ownerContact := parseContact(str, "Registrant")
	ownerContact.Role = "owner"
	r.Contacts = append(r.Contacts, ownerContact)

	adminContact := parseContact(str, "Admin")
	adminContact.Role = "admin"
	r.Contacts = append(r.Contacts, adminContact)

	techContact := parseContact(str, "Tech")
	techContact.Role = "tech"
	r.Contacts = append(r.Contacts, techContact)

	return r, err
}
