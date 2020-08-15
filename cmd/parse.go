package cmd

import (
	"github.com/spf13/cobra"
	"github.com/zerodayz/virus/helpers"
	"log"
	"time"
)

//var files []string
var (
	fileName string
	filter string
	processName string
	parserName string
	concurrency int
)

func init() {
	rootCmd.AddCommand(parseCmd)
	//parseCmd.Flags().StringSliceVar(&files, "files", []string{""}, "Input files." +
	//	"\nFor example a.log,b.log,c.log")
	parseCmd.Flags().StringVarP(&fileName, "file", "f", "", "Input file name.")
	parseCmd.Flags().StringVar(&filter, "filter", "", "Filter.")
	parseCmd.Flags().StringVarP(&processName, "process", "p", "", "Process name.")
	parseCmd.Flags().IntVarP(&concurrency, "concurrency", "c", 1, "Concurrency.")
	parseCmd.Flags().StringVar(&parserName, "parser", "generic", "Parser name.")

	parseCmd.MarkFlagRequired("file")

}


var parseCmd = &cobra.Command{
	Use:   "parse",
	Short: "Parses the logfile",
	Long:  `Parses the logfile.`,
	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		helpers.ReadFile(fileName, processName, parserName, filter, concurrency)
		end := time.Now()
		log.Println(end.Sub(start))
	},
}