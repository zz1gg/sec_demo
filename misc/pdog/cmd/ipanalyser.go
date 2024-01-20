package cmd

import (
	"github.com/spf13/cobra"
	"log"
	"pdog/internal/threaten"
)

// ipanalyserCmd represents the ipanalyser command
var ipanalyserCmd = &cobra.Command{
	Use:   "getipinfo",
	Short: "get some interesting info from target IP(single IP)",
	Long:  `get some interesting info from target IP(single IP)`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Println("IP analyser is called...")
		threaten.GeThreatcrowdIP(ips)
	},
}

func init() {
	rootCmd.AddCommand(ipanalyserCmd)

}
