package pkg

import (
	"archive/zip"
	"bytes"
	_ "bytes"
	"fmt"
	"github.com/olekukonko/tablewriter"
	"io/ioutil"
	"log"
	"os"
	"pdog/internal/metadata"
	"pdog/utils"
)

func Officeparser(target string) {

	data, err := ioutil.ReadFile(target)
	if err != nil {
		fmt.Println("File Open Failed", err)
		return
	}

	//fmt.Println(string(data))
	//defer file.Close()
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return
	}
	//fmt.Println(metadata.NewProperties(r))
	cp, ap, err := metadata.NewProperties(r)
	if err != nil {
		return
	}

	utils.GetMD5Hash(target)
	// output info table
	actions_data := [][]string{
		[]string{"MD5", utils.GetMD5Hash(target)},
		[]string{"Creator", cp.Creator},
		[]string{"LastModifiedBy", cp.LastModifiedBy},
		[]string{"Application", ap.Application},
		[]string{"OfficeVersion", ap.GetMajorVersion()},
	}
	actions_table := tablewriter.NewWriter(os.Stdout)
	actions_table.SetAutoWrapText(false)
	actions_table.SetHeader([]string{"NAME", "DESCRIPTION"})
	actions_table.SetColumnColor(
		tablewriter.Colors{},
		tablewriter.Colors{tablewriter.FgGreenColor},
	)
	for v := range actions_data {
		actions_table.Append(actions_data[v])
	}
	log.Println("The result of the analysis: ")
	actions_table.Render()

}
