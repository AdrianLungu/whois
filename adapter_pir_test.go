package whois

import (
	"testing"
)

const testStringPIRWikipedia = `Domain Name: WIKIPEDIA.ORG
Registry Domain ID: D51687756-LROR
Registrar WHOIS Server:
Registrar URL: http://www.markmonitor.com
Updated Date: 2015-12-12T10:16:19Z
Creation Date: 2001-01-13T00:12:14Z
Registry Expiry Date: 2023-01-13T00:12:14Z
Registrar Registration Expiration Date:
Registrar: MarkMonitor Inc.
Registrar IANA ID: 292
Registrar Abuse Contact Email:
Registrar Abuse Contact Phone:
Reseller:
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
Registry Registrant ID: C121149869-LROR
Registrant Name: Domain Admin
Registrant Organization: Wikimedia Foundation, Inc.
Registrant Street: 149 New Montgomery Street
Registrant Street: Third Floor
Registrant City: San Francisco
Registrant State/Province: CA
Registrant Postal Code: 94105
Registrant Country: US
Registrant Phone: +1.4158396885
Registrant Phone Ext:
Registrant Fax: +1.4158820495
Registrant Fax Ext:
Registrant Email: dns-admin@wikimedia.org
Registry Admin ID: C121149869-LROR
Admin Name: Domain Admin
Admin Organization: Wikimedia Foundation, Inc.
Admin Street: 149 New Montgomery Street
Admin Street: Third Floor
Admin City: San Francisco
Admin State/Province: CA
Admin Postal Code: 94105
Admin Country: US
Admin Phone: +1.4158396885
Admin Phone Ext:
Admin Fax: +1.4158820495
Admin Fax Ext:
Admin Email: dns-admin@wikimedia.org
Registry Tech ID: C121149869-LROR
Tech Name: Domain Admin
Tech Organization: Wikimedia Foundation, Inc.
Tech Street: 149 New Montgomery Street
Tech Street: Third Floor
Tech City: San Francisco
Tech State/Province: CA
Tech Postal Code: 94105
Tech Country: US
Tech Phone: +1.4158396885
Tech Phone Ext:
Tech Fax: +1.4158820495
Tech Fax Ext:
Tech Email: dns-admin@wikimedia.org
Name Server: NS0.WIKIMEDIA.ORG
Name Server: NS1.WIKIMEDIA.ORG
Name Server: NS2.WIKIMEDIA.ORG
DNSSEC: unsigned
URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of WHOIS database: 2017-05-07T16:26:55Z <<<

For more information on Whois status codes, please visit https://icann.org/epp

Access to Public Interest Registry WHOIS information is provided to assist persons in determining the contents of a domain name registration record in the Public Interest Registry registry database. The data in this record is provided by Public Interest Registry for informational purposes only, and Public Interest Registry does not guarantee its accuracy. This service is intended only for query-based access. You agree that you will use this data only for lawful purposes and that, under no circumstances will you use this data to: (a) allow, enable, or otherwise support the transmission by e-mail, telephone, or facsimile of mass unsolicited, commercial advertising or solicitations to entities other than the data recipient's own existing customers; or (b) enable high volume, automated, electronic processes that send queries or data to the systems of Registry Operator, a Registrar, or Afilias except as reasonably necessary to register domain names or modify existing registrations. All rights reserved. Public Interest Registry reserves the right to modify these terms at any time. By submitting this query, you agree to abide by this policy.
`

func TestPIRParser(t *testing.T) {
	r := NewResponse("wikipedia.org", "whois.pir.org")
	r.Charset = "utf-8"
	r.Body = []byte(testStringPIRWikipedia)

	record, err := r.Parse()
	if err != nil {
		t.Errorf("PIR Parse error")
	}

	/*
		(*whois.Record)(0xc420214000)({
		 Registrar: (string) (len=16) "MarkMonitor Inc.",
		 Whois: (string) "",
		 SponsoringRegistrarID: (int) 292,
		 ReferralURL: (string) (len=26) "http://www.markmonitor.com",
		 NameServers: ([]string) (len=3 cap=4) {
		  (string) (len=17) "NS0.WIKIMEDIA.ORG",
		  (string) (len=17) "NS1.WIKIMEDIA.ORG",
		  (string) (len=17) "NS2.WIKIMEDIA.ORG"
		 },
		 Status: ([]string) (len=3 cap=4) {
		  (string) (len=22) "clientDeleteProhibited",
		  (string) (len=24) "clientTransferProhibited",
		  (string) (len=22) "clientUpdateProhibited"
		 },
		 LastUpdate: (string) (len=20) "2015-12-12T10:16:19Z",
		 Expire: (string) (len=20) "2023-01-13T00:12:14Z",
		 Creation: (string) (len=20) "2001-01-13T00:12:14Z",
		 DNSSEC: (string) (len=8) "unsigned",
		 Contacts: ([]*whois.Contact) (len=3 cap=4) {
		  (*whois.Contact)(0xc42021c960)({
		   ID: (string) (len=15) "C121149869-LROR",
		   Type: (string) (len=5) "owner",
		   Name: (string) (len=12) "Domain Admin",
		   Organization: (string) (len=26) "Wikimedia Foundation, Inc.",
		   Street: ([]string) (len=2 cap=2) {
		    (string) (len=25) "149 New Montgomery Street",
		    (string) (len=11) "Third Floor"
		   },
		   City: (string) (len=13) "San Francisco",
		   StateProvince: (string) (len=2) "CA",
		   PostalCode: (string) (len=5) "94105",
		   Country: (string) (len=2) "US",
		   Phone: (string) (len=13) "+1.4158396885",
		   PhoneExt: (string) "",
		   Fax: (string) (len=13) "+1.4158820495",
		   FaxExt: (string) "",
		   Email: (string) (len=23) "dns-admin@wikimedia.org"
		  }),
		  (*whois.Contact)(0xc42021d680)({
		   ID: (string) (len=15) "C121149869-LROR",
		   Type: (string) (len=4) "tech",
		   Name: (string) (len=12) "Domain Admin",
		   Organization: (string) (len=26) "Wikimedia Foundation, Inc.",
		   Street: ([]string) (len=2 cap=2) {
		    (string) (len=25) "149 New Montgomery Street",
		    (string) (len=11) "Third Floor"
		   },
		   City: (string) (len=13) "San Francisco",
		   StateProvince: (string) (len=2) "CA",
		   PostalCode: (string) (len=5) "94105",
		   Country: (string) (len=2) "US",
		   Phone: (string) (len=13) "+1.4158396885",
		   PhoneExt: (string) "",
		   Fax: (string) (len=13) "+1.4158820495",
		   FaxExt: (string) "",
		   Email: (string) (len=23) "dns-admin@wikimedia.org"
		  }),
		  (*whois.Contact)(0xc4203803c0)({
		   ID: (string) (len=15) "C121149869-LROR",
		   Type: (string) (len=5) "admin",
		   Name: (string) (len=12) "Domain Admin",
		   Organization: (string) (len=26) "Wikimedia Foundation, Inc.",
		   Street: ([]string) (len=2 cap=2) {
		    (string) (len=25) "149 New Montgomery Street",
		    (string) (len=11) "Third Floor"
		   },
		   City: (string) (len=13) "San Francisco",
		   StateProvince: (string) (len=2) "CA",
		   PostalCode: (string) (len=5) "94105",
		   Country: (string) (len=2) "US",
		   Phone: (string) (len=13) "+1.4158396885",
		   PhoneExt: (string) "",
		   Fax: (string) (len=13) "+1.4158820495",
		   FaxExt: (string) "",
		   Email: (string) (len=23) "dns-admin@wikimedia.org"
		  })
		 }
		})
	*/

	if record.Registrar != "MarkMonitor Inc." {
		t.Errorf("PIR Parse Registrar doesn't match")
	}

	if record.Whois != "" {
		t.Errorf("PIR Parse Whois doesn't match")
	}

	if record.SponsoringRegistrarID != 292 {
		t.Errorf("PIR Parse SponsoringRegistrarID doesn't match")
	}

	if record.ReferralURL != "http://www.markmonitor.com" {
		t.Errorf("PIR Parse ReferralURL doesn't match")
	}

	if record.LastUpdate != "2015-12-12T10:16:19Z" {
		t.Errorf("PIR Parse LastUpdate doesn't match")
	}

	if record.Creation != "2001-01-13T00:12:14Z" {
		t.Errorf("PIR Parse Creation doesn't match")
	}

	if record.Expire != "2023-01-13T00:12:14Z" {
		t.Errorf("PIR Parse Expire doesn't match")
	}

	if record.DNSSEC != "unsigned" {
		t.Errorf("PIR Parse DNSSEC doesn't match")
	}

	ownerSeen := false
	techSeen := false
	adminSeen := false

	for _, c := range record.Contacts {
		if c.Type == "owner" {
			ownerSeen = true
			if c.ID != "C121149869-LROR" {
				t.Errorf("PIR Parse Owner ID doesn't match")
			}
			if c.Name != "Domain Admin" {
				t.Errorf("PIR Parse Owner Name doesn't match")
			}
			if c.Organization != "Wikimedia Foundation, Inc." {
				t.Errorf("PIR Parse Owner Organization doesn't match")
			}

		} else if c.Type == "tech" {
			techSeen = true
			if c.ID != "C121149869-LROR" {
				t.Errorf("PIR Parse Tech ID doesn't match")
			}
			if c.Name != "Domain Admin" {
				t.Errorf("PIR Parse Tech Name doesn't match")
			}
			if c.Organization != "Wikimedia Foundation, Inc." {
				t.Errorf("PIR Parse Tech Organization doesn't match")
			}

		} else if c.Type == "admin" {
			adminSeen = true
			if c.ID != "C121149869-LROR" {
				t.Errorf("PIR Parse Admin ID doesn't match")
			}
			if c.Name != "Domain Admin" {
				t.Errorf("PIR Parse Admin Name doesn't match")
			}
			if c.Organization != "Wikimedia Foundation, Inc." {
				t.Errorf("PIR Parse Admin Organization doesn't match")
			}
		}
	}

	if ownerSeen != true {
		t.Errorf("PIR Parse Missing Owner Contact")
	}

	if techSeen != true {
		t.Errorf("PIR Parse Missing Tech Contact")
	}

	if adminSeen != true {
		t.Errorf("PIR Parse Missing Admin Contact")
	}
}
