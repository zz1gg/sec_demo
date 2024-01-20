package cmd

import (
	"github.com/spf13/cobra"
)

var targetfile string
var filetype string
var domains string
var ips string
var ipsfile string

var rootCmd = &cobra.Command{
	Use:   "",
	Short: "",
	Long:  "",
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(fileanalyserCmd)
	rootCmd.PersistentFlags().StringVarP(&targetfile, "targetfile", "f", "", "specify the target [filetype: doc|docx|xlsx|ppt|pdf|exe|elf...]")
	rootCmd.PersistentFlags().StringVarP(&ips, "ip", "i", "", "specify the target Single IP")
	rootCmd.PersistentFlags().StringVarP(&domains, "domain", "d", "", "specify the target domain")
	rootCmd.PersistentFlags().StringVarP(&ipsfile, "ipsfile", "", "", "specify the target ips file")

}
