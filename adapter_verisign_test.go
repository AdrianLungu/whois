package whois

import (
	"testing"
)

const testStringVerisign = `Whois Server Version 2.0

Domain names in the .com and .net domains can now be registered
with many different competing registrars. Go to http://www.internic.net
for detailed information.

   Domain Name: GOOGLE.COM
   Registrar: MARKMONITOR INC.
   Sponsoring Registrar IANA ID: 292
   Whois Server: whois.markmonitor.com
   Referral URL: http://www.markmonitor.com
   Name Server: NS1.GOOGLE.COM
   Name Server: NS2.GOOGLE.COM
   Name Server: NS3.GOOGLE.COM
   Name Server: NS4.GOOGLE.COM
   Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
   Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
   Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited
   Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited
   Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited
   Updated Date: 20-jul-2011
   Creation Date: 15-sep-1997
   Expiration Date: 14-sep-2020

>>> Last update of whois database: Sun, 07 May 2017 16:39:23 GMT <<<

For more information on Whois status codes, please visit https://icann.org/epp

NOTICE: The expiration date displayed in this record is the date the
registrar's sponsorship of the domain name registration in the registry is
currently set to expire. This date does not necessarily reflect the expiration
date of the domain name registrant's agreement with the sponsoring
registrar.  Users may consult the sponsoring registrar's Whois database to
view the registrar's reported date of expiration for this registration.

TERMS OF USE: You are not authorized to access or query our Whois
database through the use of electronic processes that are high-volume and
automated except as reasonably necessary to register domain names or
modify existing registrations; the Data in VeriSign Global Registry
Services' ("VeriSign") Whois database is provided by VeriSign for
information purposes only, and to assist persons in obtaining information
about or related to a domain name registration record. VeriSign does not
guarantee its accuracy. By submitting a Whois query, you agree to abide
by the following terms of use: You agree that you may use this Data only
for lawful purposes and that under no circumstances will you use this Data
to: (1) allow, enable, or otherwise support the transmission of mass
unsolicited, commercial advertising or solicitations via e-mail, telephone,
or facsimile; or (2) enable high volume, automated, electronic processes
that apply to VeriSign (or its computer systems). The compilation,
repackaging, dissemination or other use of this Data is expressly
prohibited without the prior written consent of VeriSign. You agree not to
use electronic processes that are automated and high-volume to access or
query the Whois database except as reasonably necessary to register
domain names or modify existing registrations. VeriSign reserves the right
to restrict your access to the Whois database in its sole discretion to ensure
operational stability.  VeriSign may restrict or terminate your access to the
Whois database for failure to abide by these terms of use. VeriSign
reserves the right to modify these terms at any time.

The Registry database contains ONLY .COM, .NET, .EDU domains and
Registrars.
Invalid query`

func TestVerisignParser(t *testing.T) {
	r := NewResponse("google.com", "whois.verisign-grs.com")
	r.Charset = "utf-8"
	r.Body = []byte(testStringVerisign)

	record, err := r.Parse()
	if err != nil {
		t.Errorf("Verisign Parse error")
	}
	/*
		 (*whois.Record)(0xc42022a000)({
		 Registrar: (string) (len=16) "MARKMONITOR INC.",
		 Whois: (string) (len=21) "whois.markmonitor.com",
		 SponsoringRegistrarID: (int) 292,
		 ReferralURL: (string) (len=26) "http://www.markmonitor.com",
		 NameServers: ([]string) (len=4 cap=4) {
		  (string) (len=14) "NS1.GOOGLE.COM",
		  (string) (len=14) "NS2.GOOGLE.COM",
		  (string) (len=14) "NS3.GOOGLE.COM",
		  (string) (len=14) "NS4.GOOGLE.COM"
		 },
		 Status: ([]string) (len=6 cap=8) {
		  (string) (len=22) "clientDeleteProhibited",
		  (string) (len=24) "clientTransferProhibited",
		  (string) (len=22) "clientUpdateProhibited",
		  (string) (len=22) "serverDeleteProhibited",
		  (string) (len=24) "serverTransferProhibited",
		  (string) (len=22) "serverUpdateProhibited"
		 },
		 LastUpdate: (string) (len=11) "20-jul-2011",
		 Expire: (string) (len=11) "14-sep-2020",
		 Creation: (string) (len=11) "15-sep-1997",
		 DNSSEC: (string) "",
		 Contacts: ([]*whois.Contact) <nil>
		})
	*/
	if record.Registrar != "MARKMONITOR INC." {
		t.Errorf("Verisign Parse Registrar doesn't match")
	}

	if record.Whois != "whois.markmonitor.com" {
		t.Errorf("Verisign Parse Whois doesn't match")
	}

	if record.SponsoringRegistrarID != 292 {
		t.Errorf("Verisign Parse SponsoringRegistrarID doesn't match")
	}

	if record.ReferralURL != "http://www.markmonitor.com" {
		t.Errorf("Verisign Parse ReferralURL doesn't match")
	}

	if record.LastUpdate != "20-jul-2011" {
		t.Errorf("Verisign Parse LastUpdate doesn't match")
	}

	if record.Creation != "15-sep-1997" {
		t.Errorf("Verisign Parse Creation doesn't match")
	}

	if record.Expire != "14-sep-2020" {
		t.Errorf("Verisign Parse Expire doesn't match")
	}
}
