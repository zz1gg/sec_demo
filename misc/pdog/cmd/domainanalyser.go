package cmd

import (
	"log"
	"pdog/internal/threaten"

	"github.com/spf13/cobra"
)

// domainanalyserCmd represents the domainanalyser command
var domainanalyserCmd = &cobra.Command{
	Use:   "getdomaininfo",
	Short: "get some interesting info from target domain",
	Long:  `get some interesting info from target domain`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Println("Domain analyser is called...")
		threaten.GeThreatcrowdDomain(domains)

	},
}

func init() {
	rootCmd.AddCommand(domainanalyserCmd)


}
