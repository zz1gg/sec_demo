package cmd

import (
	"log"
	"pdog/internal/threaten"
	"pdog/pkg"
	"pdog/utils"

	"github.com/spf13/cobra"
)

// fileanalyserCmd represents the metadatapaser command
var fileanalyserCmd = &cobra.Command{
	Use:   "getfileinfo",
	Short: "get some interesting info from target file",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		log.Println("File analyser is called...")
		//fmt.Println(target)
		//pkg.Officeparser(target)
		//pkg.PDFparser(target)

		switch utils.CheckFileType(targetfile) {
		case 1:
			log.Println("The target file is Office Document...")
			pkg.Officeparser(targetfile)
			//fmt.Println(utils.GetMD5Hash(target))
			threaten.GEThreatCorwdResources(utils.GetMD5Hash(targetfile))

			//threaten.GEThreatCorwdResources(target)
		case 2:
			log.Println("The target file is PDF Document...")
			pkg.PDFparser(targetfile)
			threaten.GEThreatCorwdResources(utils.GetMD5Hash(targetfile))
		//log.Println("Search related threaten...")
		//threaten.GEThreatCorwdResources(target)
		//threaten.GEThreatCorwdResources(utils.GetMD5Hash(target))
		case 3:
			log.Println("The target file is Windows executable program...")
			threaten.GEThreatCorwdResources(utils.GetMD5Hash(targetfile))
		case 4:
			log.Println("The target file is Executable Linkable Format ")
			threaten.GEThreatCorwdResources(utils.GetMD5Hash(targetfile))
		default:
			log.Fatalf("Ohhh, it's unknown file! Maybe this file has some problem...")
			threaten.GEThreatCorwdResources(utils.GetMD5Hash(targetfile))
		}
		//fmt.Println(metadata.NewPropertiesFromPDFDoc(target))
	},
}

func init() {

}
