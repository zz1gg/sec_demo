package pkg

import (
	"bufio"
	"fmt"
	"github.com/thinkeridea/go-extend/exnet"
	"log"
	"net"
	"os"
)

var getiperrors error
var ips []string


func GetIPSList(targetFile string) []string {
	iplists, err := ReadFile(targetFile)

	iplists = unique(iplists)

	if err != nil {
		log.Printf("Target file is wrong, the reason is %v\r\n", err)
		os.Exit(0)
	}
	return removenotip(iplists)

	//return sliceToStrMap(removenotip(iplists))

}

//Read target file
func ReadFile(targetFile string) ([]string, error) {
	file, err := os.Open(targetFile)
	if err != nil {
		getiperrors = err
		return nil, getiperrors
	}
	defer func() {
		if err = file.Close(); err != nil {
			log.Fatal(err)
			getiperrors = err
		}
	}()
	s := bufio.NewScanner(file)
	for s.Scan() {
		ips = append(ips, s.Text())
		//fmt.Println(s.Text())
	}
	//fmt.Println(ips)
	err = s.Err()
	if err != nil {
		//log.Fatal(err)
		getiperrors = err
		return nil, getiperrors
	}
	return ips, getiperrors
}

//duplication
func unique(ips []string) []string {
	keys := make(map[string]bool)
	iplist := []string{}
	for _, entry := range ips {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			iplist = append(iplist, entry)
		}
	}
	return iplist
}

//Remove invalid IP from the array
func removenotip(ips []string) []string {
	//var elements []string
	ipsMap := make(map[int]string)
	for i, ip := range ips {
		ipsMap[i] = ip
	}
	//fmt.Println(ipsMap)
	//Check whether the IP is valid
	log.Println("Checking the IP format...")
	fmt.Println("------------------------------------------------------------------")
	for num, ip := range ipsMap {
		if net.ParseIP(ip) == nil {
			log.Printf("%s ip address format is incorrect! Removed from the target！\r\n", ipsMap[num])
			delete(ipsMap, num)
		}

	}
	fmt.Println("------------------------------------------------------------------")
	log.Println("Remove the intranet IP...")
	for i, j := range ipsMap{
		if exnet.HasLocalIPAddr(j) == true {
			delete(ipsMap,i)
		}
	}
	iplists := mapToSlice(ipsMap)
	return iplists
}

//Convert map to array
func mapToSlice(ipsMap map[int]string) []string {
	ips := make([]string, 0, len(ipsMap))
	for _, v := range ipsMap {
		ips = append(ips, v)
	}
	return ips
}

func sliceToStrMap(ipsLists []string) map[int]string {
	ipsMap := make(map[int]string)
	for n, s := range ipsLists {
		ipsMap[n] = s
	}
	return ipsMap
}


