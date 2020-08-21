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
	Short: "Print the version number of Depthh",
	Long:  `Version of the Depthh - a tool.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Depthh - a tool")
	},
}