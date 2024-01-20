package threaten

import (
	"fmt"
	"github.com/jheise/gothreat"
	"log"
	"net"
	"pdog/utils"
)

func GeThreatcrowdDomain(domains string) {

	//fmt.Println(GetMD5Hash("Test.pdf"))
	//ipData, err := gothreat.IPReport("188.40.75.132")
	if !utils.ValidateDomainName(domains) {
		fmt.Printf("Domain Name %s is invalid\r\n", domains)
	} else {
		//log.Println("Domain Name %s is VALID\n", domName)
		ips, err := net.LookupIP(domains)
		if err != nil {
			log.Println(err)
		}
		fmt.Println(domains, "'s IP is: ")
		fmt.Println("----------------------------------------")
		for _, ip := range ips {
			fmt.Println(ip.String())
		}
		fmt.Println("----------------------------------------")

		domainData, err := gothreat.DomainReport(domains)
		if err != nil {
			log.Fatalf("Query data from threatcrowd failed with: ", err)
		}

		fmt.Printf("Permalink: %s\n", domainData.Permalink)
		fmt.Printf("Reverse DNS Resolutions:\n")
		for _, resolve := range domainData.Resolutions {
			fmt.Printf("\t%v -> %v\n", resolve.LastResolved, resolve.IPAddress)
		}
		fmt.Printf("References:\n")
		for _, reference := range domainData.References {
			fmt.Printf("\t%s\n", reference)
		}
		fmt.Printf("Releated Malware Hashes:\n")
		for _, hash := range domainData.Hashes {
			fmt.Printf("\t%s\n", hash)
		}
		fmt.Printf("Releated Emails:\n")
		for _, email := range domainData.Emails {
			fmt.Printf("\t%s\n", email)
		}
		fmt.Printf("Releated Emails:\n")
		for _, subdomain := range domainData.Subdomains {
			fmt.Printf("\t%s\n", subdomain)
		}
	}
}
