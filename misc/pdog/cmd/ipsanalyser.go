package cmd

import (
	"fmt"
	"log"
	"pdog/internal/threaten"
	"pdog/pkg"
	"strings"

	"github.com/spf13/cobra"
)

var ThreadNum int

// ipsanalyserCmd represents the ipsanalyser command
var ipsanalyserCmd = &cobra.Command{
	Use:   "ipsanalyser",
	Short: "get some interesting info from target IP(Multiple IPs)",
	Long: `get some interesting info from target IP(Multiple IPs)`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("IPs analyser are called...")

		//pkg.GetIPSList(ipsfile)
		//threaten.GeThreatcrowdIPResluts(ips, ipsfile)

		IPSLists := pkg.GetIPSList(ipsfile)
		log.Println("Final IP：", IPSLists)

		tasks, _ := threaten.GenerateTask(IPSLists)
		//fmt.Println("tasks: ", tasks)
		//threaten.AssigningTasks(tasks)
		fmt.Println(strings.Repeat("-", 100))
		threaten.RunTask(tasks, ThreadNum)
	},
}

func init() {
	rootCmd.AddCommand(ipsanalyserCmd)
	rootCmd.PersistentFlags().IntVarP(&ThreadNum,"thread", "", 200, "set thread number")
}
