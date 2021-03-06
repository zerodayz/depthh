package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/zerodayz/depthh/helpers"
	"log"
	"os"
	"time"
)

//var files []string
var (
	fileName string
	filter string
	processName string
	showHostname bool
	priority int
	analysis bool
	ignoreErrors bool
	sinceTime string
	untilTime string
)

func init() {
	rootCmd.AddCommand(parseCmd)
	//parseCmd.Flags().StringSliceVar(&files, "files", []string{""}, "Input files." +
	//	"\nFor example a.log,b.log,c.log")
	parseCmd.Flags().StringVarP(&fileName, "file", "f", "", "Location of the logging file.")
	parseCmd.Flags().StringVarP(&filter, "filter", "F", "", "Filter output by message.")
	parseCmd.Flags().StringVarP(&sinceTime, "since", "S", "" ,"Show entries newer than the specified date. " +
		"Date should be of the format \"Aug 5 17:58:06\".")
	parseCmd.Flags().StringVarP(&untilTime, "until", "U","" ,"Show entries older than the specified date. " +
		"Date should be of the format \"Aug 12 05:14:42\".")
	parseCmd.Flags().StringVarP(&processName, "process", "P", "", "Show messages for the specified process.")
	parseCmd.Flags().IntVarP(&priority, "priority", "p", 5, "Filter output by message priority." +
		"\"fatal\" (1), \"error\" (2), \"warning\" (3), \"info\" (4), \"debug\" (5).")
	parseCmd.Flags().BoolVarP(&showHostname, "show-hostname", "H", false, "Show hostname along the messages.")
	parseCmd.Flags().BoolVarP(&analysis, "summary", "s", false, "Show executive summary.")
	parseCmd.Flags().BoolVarP(&ignoreErrors, "ignore-errors", "I", false, "Ignore parsing errors.")
	parseCmd.MarkFlagRequired("file")

}


var parseCmd = &cobra.Command{
	Use:   "parse",
	Short: "Parses the logfile",
	Long:  `Parses the logfile.`,
	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		file, err := os.Open(fileName)
		if err != nil {
			fmt.Println("Unable to read the file.", err)
			return
		}

		defer func() {
			if err := file.Close(); err != nil {
				return
			}
		}()

		sinceTime, err := time.Parse("Jan 2 15:04:05", sinceTime)
		if err != nil {
			fmt.Println("Wrong \"since\" date and time format. Date should be of the format \"Aug 5 17:58:06\".")
			return
		}
		untilTime, err := time.Parse("Jan 2 15:04:05", untilTime)
		if err != nil {
			fmt.Println("Wrong \"until\" date and time format. Date should be of the format \"Aug 5 17:58:06\".")
			return
		}

		err = helpers.ParseFile(file, sinceTime, untilTime, processName, filter, priority, analysis, ignoreErrors, showHostname)
		if err != nil {
			return
		}

		end := time.Now()
		log.Println(end.Sub(start))
	},
}