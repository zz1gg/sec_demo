package threaten

import (
	"fmt"
	"github.com/jheise/gothreat"
	"log"
	"net"
	"strings"
	"sync"
)
//[23.129.64.143 182.52.16.226 199.168.172.2 149.210.175.3 188.40.75.132]
func GenerateTask(ipList []string) ([]map[int]string, int) {
	tasks := make([]map[int]string, 0)

	for n, ip := range ipList {

			ipLists := map[int]string{n: ip}
			tasks = append(tasks, ipLists)
		}
	return tasks, len(tasks)
}

func RunTask(tasks []map[int]string, ThreadNum int) {
	wg := &sync.WaitGroup{}
	// create buffer: vars.threadNum * 2 channel
	taskChan := make(chan map[int]string, ThreadNum*2)
	// create vars.ThreadNum Coroutine
	for i := 0; i < ThreadNum; i++ {
		go Scan(taskChan, wg)
	}
	// The producer continuously sends data to the taskChan channel, directly blocking the channel
	for _, task := range tasks {
		wg.Add(1)
		taskChan <- task
	}

	close(taskChan)
	wg.Wait()
}

func Scan(taskChan chan map[int]string, wg *sync.WaitGroup) {
	// Each coroutine reads the data from the channel and starts scanning and storing it in the library
	for task := range taskChan {
		for _, ip := range task {
			GeThreatcrowdIP(ip)
			wg.Done()
			fmt.Println(strings.Repeat("=", 100))
		}
	}
}


func GeThreatcrowdIP(ips string) {

	//fmt.Println(GetMD5Hash("Test.pdf"))
	//ipData, err := gothreat.IPReport("188.40.75.132")
	// parse IP to domain
	/*
	addrs, err := net.LookupAddr(ips)
	if err != nil {
		log.Println("Cause problems: ", err)
	}
	//fmt.Println(addrs)
	fmt.Println(ips, "'s domain is: ")
	//fmt.Println("----------------------------------------")
	for _, addr := range addrs {
		fmt.Println(addr)
	}

	 */
	//fmt.Println("----------------------------------------")
	address := net.ParseIP(ips)
	if address == nil {
		log.Fatalf("The target is not IP!")
	} else {
		//log.Println("The target is IP", address.String())

		ipData, err := gothreat.IPReport(ips)
		if err != nil {
			log.Println(err)
		}


		addrs, err := net.LookupAddr(ips)
		if err != nil {
			fmt.Println("Cause problems: ", err)
		}
		fmt.Println(ips, "Domain is: ", addrs)

		fmt.Printf("Permalink: %s\n", ipData.Permalink)
		fmt.Printf("Reverse DNS Resolutions:\n")
		for _, resolve := range ipData.Resolutions {
			fmt.Printf("\t%v -> %v\n", resolve.LastResolved, resolve.Domain)
		}
		fmt.Printf("References:\n")
		for _, reference := range ipData.References {
			fmt.Printf("\t%s\n", reference)
		}
		fmt.Printf("Releated Malware Hashes:\n")
		for _, hash := range ipData.Hashes {
			fmt.Printf("\t%s\n", hash)
		}

	}
}
