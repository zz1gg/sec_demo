package threaten

import (
	"encoding/json"
	"fmt"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"golang.org/x/text/encoding/simplifiedchinese"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

type ThreatCorwdResource struct {
	ResponseCode string        `json:"response_code"`
	Md5          string        `json:"md5"`
	Sha1         string        `json:"sha1"`
	Scans        []string      `json:"scans"`
	Ips          []string      `json:"ips"`
	Domains      []string      `json:"domains"`
	References   []interface{} `json:"references"`
	Permalink    string        `json:"permalink"`
}

const threatcorwdurl = "https://www.threatcrowd.org/searchApi/v2"

//GET GEThreatCorwdResources File results
func GEThreatCorwdResources(target string) *ThreatCorwdResource {

	client := &http.Client{}
	//var target = "159.203.93.255"

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/file/report/?resource=%s", threatcorwdurl, target), nil)
	//req, _ := http.NewRequest("GET",target, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.128 Safari/537.36")

	req.Header.Add("Accept-Charset", "utf-8")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("%s\n", err.Error())

	}
	defer resp.Body.Close()

	reader := simplifiedchinese.GB18030.NewDecoder().Reader(resp.Body)
	bodydata, err := ioutil.ReadAll(reader)
	if err != nil {
		fmt.Printf("GE ThreatCorwdResources Request Error：%s\n", err.Error())
	}
	var threatcorwdresource ThreatCorwdResource

	err = json.Unmarshal(bodydata, &threatcorwdresource)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	//fmt.Println(threatcorwdresource)
	if threatcorwdresource.ResponseCode == "0" {
		log.Println("Query From ThreatCorwd Failed! Maybe No Data!")
	} else {
		//fmt.Println("File MD5: ",threatcorwdresource.Md5)
		//fmt.Println("File Sha1: ",threatcorwdresource.Sha1)
		fmt.Println("File related Domain: ", threatcorwdresource.Domains)

		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{"NAME", "DESCRIPTION"})
		t.AppendRows([]table.Row{
			{"File MD5 ", threatcorwdresource.Md5},
			{"File Sha1 ", threatcorwdresource.Sha1},
		})

		for _, S := range threatcorwdresource.Scans {
			t.AppendRow([]interface{}{"File related Antivirus Tag", S})
		}
		for _, k := range threatcorwdresource.Domains {
			t.AppendRow([]interface{}{"File related Domains", k})
		}
		for _, I := range threatcorwdresource.Ips {
			t.AppendRow([]interface{}{"File related IPS", I})
		}
		t.Style().Options.SeparateRows = true

		t.SetColumnConfigs([]table.ColumnConfig{
			{Number: 1, AutoMerge: true},
			//{Number: 2, AutoMerge: true},
			{Number: 3, AutoMerge: true},
			{Number: 4, AutoMerge: true},
			{Number: 5, Align: text.AlignCenter, AlignFooter: text.AlignCenter, AlignHeader: text.AlignCenter},
			{Number: 6, Align: text.AlignCenter, AlignFooter: text.AlignCenter, AlignHeader: text.AlignCenter},
		})
		t.Render()
	}
	return &threatcorwdresource
}
