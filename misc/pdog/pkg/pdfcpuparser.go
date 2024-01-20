package pkg

import (
	"fmt"
	"github.com/olekukonko/tablewriter"
	"github.com/pdfcpu/pdfcpu/pkg/api"
	"log"
	"os"
	"pdog/utils"
)

//parse pdf interesting info
func PDFparser(target string) {

	//api.ExtractMetadataFile("Test.pdf", ".",nil)
	pdffile, err := api.ReadContextFile(target)
	if err != nil {
		fmt.Println(err)
	}
	//fmt.Println(pdffile.Author, pdffile.Creator, pdffile.Producer ,pdffile.CreationDate,pdffile.ModDate, pdffile.HeaderVersion)

	// output info table
	actions_data := [][]string{
		[]string{"MD5", utils.GetMD5Hash(target)},
		[]string{"Author", pdffile.Author},
		[]string{"Creator", pdffile.Creator},
		[]string{"Producer", pdffile.Producer},
		[]string{"Creation Date", pdffile.CreationDate},
		[]string{"Modify Date", pdffile.ModDate},
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
