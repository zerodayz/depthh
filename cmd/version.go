package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of Virus",
	Long:  `Version of the Virus - a tool.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Virus - a tool")
	},
}