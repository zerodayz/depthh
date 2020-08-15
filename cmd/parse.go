package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/zerodayz/virus/helpers"
	"log"
	"os"
	"time"
)

//var files []string
var (
	fileName string
	filter string
	processName string
	parserName string
	concurrency int
	sinceTime string
	untilTime string
)

func init() {
	rootCmd.AddCommand(parseCmd)
	//parseCmd.Flags().StringSliceVar(&files, "files", []string{""}, "Input files." +
	//	"\nFor example a.log,b.log,c.log")
	parseCmd.Flags().StringVarP(&fileName, "file", "f", "", "Location of the logging file.")
	parseCmd.Flags().StringVarP(&filter, "filter", "F", "", "Filter output by message.")
	parseCmd.Flags().StringVarP(&sinceTime, "since", "S", "" ,"Shows entries newer than the specified date. " +
		"Date should be of the format \"Aug 5 17:58:06\".")
	parseCmd.Flags().StringVarP(&untilTime, "until", "U","" ,"Shows entries older than the specified date." +
		"Date should be of the format \"Aug 12 05:14:42\".")
	parseCmd.Flags().StringVarP(&processName, "process", "p", "", "Show messages for the specified process.")

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
		defer file.Close()

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

		helpers.ParseFile(file, sinceTime, untilTime, processName, filter)
		end := time.Now()
		log.Println(end.Sub(start))
	},
}