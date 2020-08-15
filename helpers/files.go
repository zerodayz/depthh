package helpers

import (
	"bufio"
	"fmt"
	"github.com/orcaman/concurrent-map"
	"io"
	"math"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var wg sync.WaitGroup

func ParseFile(file *os.File, sinceTime, untilTime time.Time, processName, filter string, priority int) error {
	linesPool := sync.Pool{New: func() interface{} {
		lines := make([]byte, 1024*1024)
		return lines
	}}

	stringPool := sync.Pool{New: func() interface{} {
		lines := ""
		return lines
	}}
	r := bufio.NewReader(file)
	var wg sync.WaitGroup

	for {
		buf := linesPool.Get().([]byte)
		n, err := r.Read(buf)
		buf = buf[:n]
		if n == 0 {
			if err != nil {
				fmt.Println(err)
				break
			}
			if err == io.EOF {
				break
			}
			return err
		}
		nextUntilNewline, err := r.ReadBytes('\n')
		if err != io.EOF {
			buf = append(buf, nextUntilNewline...)
		}
		wg.Add(1)
		go func() {
			ProcessChunk(buf, &linesPool, &stringPool, sinceTime, untilTime, processName, filter, priority)
			wg.Done()
		}()
	}
	wg.Wait()
	return nil
}

func ProcessChunk(chunk []byte, linesPool, stringPool *sync.Pool, sinceTime, untilTime time.Time, processName, filter string, priority int) {
	var wg2 sync.WaitGroup
	var logCreationTimeString string

	makeMap := cmap.New()

	logs := stringPool.Get().(string)
	logs = string(chunk)

	linesPool.Put(chunk)
	logsSlice := strings.Split(logs, "\n")
	stringPool.Put(logs)

	chunkSize := 300
	n := len(logsSlice)
	noOfThread := n / chunkSize

	if n%chunkSize != 0 {
		noOfThread++
	}

	for i := 0; i < (noOfThread); i++ {

		wg2.Add(1)
		go func(s int, e int) {
			defer wg2.Done() //to avaoid deadlocks
			for i := s; i < e; i++ {
				text := logsSlice[i]
				if len(text) == 0 {
					continue
				}

				logLine := regexp.MustCompile(`^(?P<Date>(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+[0-9]+` +
					`\s+[0-9]+:[0-9]+:[0-9]+)` +
					`\s+(?P<Hostname>[0-9A-Za-z\.\-]*)` +
					`\s+(?P<ProcessName>[0-9A-Za-z\.\-]*)` +
					`(\[)?` +
					`(?P<ProcessPID>[0-9]+)?` +
					`(\])?:` +
					`\s+(?P<Message>.*)`)

				match := logLine.FindStringSubmatch(text)

				for i, name := range logLine.SubexpNames() {
					if i > 0 && i <= len(match) {
						makeMap.Set(name, match[i])
					}
				}

				if tmp, ok := makeMap.Get("Date"); ok {
					logCreationTimeString = tmp.(string)
				}

				logCreationTime, err := time.Parse("Jan 2 15:04:05", logCreationTimeString)
				if err != nil {
					fmt.Println(Red + "Unable to parse date and time format. Date should be of the format \"Aug 5 17:58:06\". " + logCreationTimeString + Reset)
					return
				}

				if logCreationTime.After(sinceTime) && logCreationTime.Before(untilTime) {
					FilterLog(makeMap, processName, filter)
				}
			}


		}(i*chunkSize, int(math.Min(float64((i+1)*chunkSize), float64(len(logsSlice)))))
	}

	wg2.Wait()
	logsSlice = nil
}

func FilterLog(makeMap cmap.ConcurrentMap, processName, filter string) {


	var logDate, logProcessName, logMessage string
	var processNameCompiled = regexp.MustCompile(processName)
	var filterCompiled = regexp.MustCompile(filter)

	if tmp, ok := makeMap.Get("Date"); ok {
		logDate = tmp.(string)
	}
	if tmp, ok := makeMap.Get("ProcessName"); ok {
		logProcessName = tmp.(string)
	}
	if tmp, ok := makeMap.Get("Message"); ok {
		logMessage = tmp.(string)
	}
	if processNameCompiled.MatchString(logProcessName) &&
		filterCompiled.MatchString(logMessage) {
		fmt.Println(Blue + logDate + Reset + " " + Yellow + logProcessName + Reset + " " + logMessage)
	}
}