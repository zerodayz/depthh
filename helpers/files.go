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

func ParseFile(file *os.File, sinceTime, untilTime time.Time, processName, filter string, priority int, analysis, podLogs bool) error {
	linesPool := sync.Pool{New: func() interface{} {
		lines := make([]byte, 250*1024)
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
			ProcessChunk(buf, &linesPool, &stringPool, sinceTime, untilTime, processName, filter, priority, analysis, podLogs)
			wg.Done()
		}()
	}
	wg.Wait()
	return nil
}

func ProcessChunk(chunk []byte, linesPool, stringPool *sync.Pool, sinceTime, untilTime time.Time, processName, filter string, priority int, analysis, podLogs bool) {
	var logCreationTimeString string
	var logLine *regexp.Regexp
	var logCreationTime time.Time
	var err error

	logs := stringPool.Get().(string)
	logs = string(chunk)

	linesPool.Put(chunk)
	logsSlice := strings.Split(logs, "\n")
	stringPool.Put(logs)

	chunkSize := 4000
	n := len(logsSlice)
	noOfThread := n / chunkSize

	if n%chunkSize != 0 {
		noOfThread++
	}

	makeMap := cmap.New()
	for i := 0; i < (noOfThread); i++ {
		for i := i*chunkSize; i < int(math.Min(float64((i+1)*chunkSize), float64(len(logsSlice)))); i++ {
			text := logsSlice[i]
			if len(text) == 0 {
				continue
			}

			if podLogs {
				// 2020-08-14T02:46:41.537460623Z 2020-08-14 02:46:41.537423 I | mvcc: store.index: compact 1535691
				logLine = regexp.MustCompile(`^(?P<Date>[0-9]+-[0-9]+-[0-9]+T[0-9]+:[0-9]+:[0-9]+\.[0-9]+Z)\s+` +
					`([0-9]+-[0-9]+-[0-9]+\s[0-9]+:[0-9]+:[0-9]+.[0-9]+\s+)?` +
					`(?P<Message>.*)`)
			} else {
				logLine = regexp.MustCompile(`^(?P<Date>(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+[0-9]+` +
					`\s+[0-9]+:[0-9]+:[0-9]+)` +
					`\s+(?P<Hostname>[0-9A-Za-z\.\-]*)` +
					`\s+(?P<ProcessName>[0-9A-Za-z\.\-]*)` +
					`(\[)?` +
					`(?P<ProcessPID>[0-9]+)?` +
					`(\])?:` +
					`\s+(?P<Message>.*)`)
			}

			match := logLine.FindStringSubmatch(text)

			for i, name := range logLine.SubexpNames() {
				if i > 0 && i <= len(match) {
					makeMap.Set(name, match[i])
				}
			}

			if tmp, ok := makeMap.Get("Date"); ok {
				logCreationTimeString = tmp.(string)
			}

			if podLogs {
				logCreationTime, err = time.Parse("2006-01-02T15:04:05.999999999Z", logCreationTimeString)
				if err != nil {
					fmt.Println(Red + "Unable to parse date and time format. Date should be of the format \"Aug 5 17:58:06\":\n " + text + Reset)
				}
			} else {
				logCreationTime, err = time.Parse("Jan 2 15:04:05", logCreationTimeString)
				if err != nil {
					fmt.Println(Red + "Unable to parse date and time format. Date should be of the format \"Aug 5 17:58:06\":\n " + text + Reset)
				}
			}
			if logCreationTime.After(sinceTime) && logCreationTime.Before(untilTime) {
				FilterLog(makeMap, processName, filter, priority, analysis, podLogs)
			}
		}
	}
	logsSlice = nil
}

func FilterLog(makeMap cmap.ConcurrentMap, processName, filter string, priority int, analysis, podLogs bool) {
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

	// podman (remove date/time+stamp (rcernin))
	podmanDateTime := regexp.MustCompile(`[0-9]+-[0-9]+-[0-9]+\s+[0-9]+:[0-9]+:[0-9]+\.[0-9]+\s+[+-][0-9]+\s+UTC` +
		`\s+m=[+-][0-9]+\.[0-9]+\s+`)

	// hyperkube (remove date/time+stamp (rcernin))
	hyperkubeDateTime := regexp.MustCompile(
		// 0805 17:54:15.628339
		`[0-9]+\s+[0-9]+:[0-9]+:[0-9]+\.[0-9]+` +
			`\s+[0-9]+` +
			// panics.go:76]
			`\s+[A-Za-z\.\_\-]+:[0-9]+\]`)

	// hyperkube (remove un-needed information from informational messages (rcernin))
	hyperkubeInfoFilter := regexp.MustCompile(
		`(\s+[A-Z]+\s+)` +
			`([\/a-zA-Z0-9\-\%\?\=\&\.]+:\s\([0-9.a-zµ]+\)\s+[0-9]+\s+)` +
			`\[.*\]\s` +
			`([0-9\.\:]+)\]`)

	// hyperkube (replace IWEF with INFO/WARN/ERR/FATAL)
	hyperkubeTypeI := regexp.MustCompile(`^I\s+|^\[INFO\]\s+`)
	hyperkubeTypeW := regexp.MustCompile(`^W\s+`)
	hyperkubeTypeE := regexp.MustCompile(`^E\s+|^Error:\s+`)
	hyperkubeTypeF := regexp.MustCompile(`^F\s+|^C\s+`)
	hyperkubeTypeIn := regexp.MustCompile(`^(,StartedAt)`)

	// systemd (replace info, error messages)
	systemdTypeI := regexp.MustCompile(`^(Started|Starting|Created|Stopping|Removed|New session|.*Consumed)`)
	systemdTypeF := regexp.MustCompile(`^(Failed)`)
	systemdTypeE := regexp.MustCompile(`^(.*Main process exited|.*Failed with result)`)

	// dhclient (replace info, error message)
	dhclientTypeI := regexp.MustCompile(`^(DHCPREQUEST|DHCPACK|bound to)`)

	// etcd
	etcdTypeW := regexp.MustCompile(`^(health check for peer.*connect:.*connection refused)`)

	// podman
	podmanTypeI := regexp.MustCompile(`^(container)`)

	// podlog process
	podLogsProcessName := regexp.MustCompile(`[A-Z]+\s+\|\s+([A-Za-z0-9\-\/\.\_]+):.*`)
	podLogsRemoveProcessName := regexp.MustCompile(`\s+\|\s+([A-Za-z0-9\-\/\.\_]+):`)

	// NetworkManager
	networkManagerTypeI := regexp.MustCompile(`^(<info>)`)

	// global messages
	informationalMessage := regexp.MustCompile(`^\[32mINFO`)
	// warningMessage := regexp.MustCompile(`^WARNING`)
	errorMessage := regexp.MustCompile(`^\[31mERROR`)
	fatalMessage := regexp.MustCompile(`^\[35mFATAL`)
	debugMessage := regexp.MustCompile(`^DEBUG`)

	// Filter out Date + Time+stamp on each line
	// because we keep the system Date + Time+stamp
	if logProcessName == "podman" {
		logMessage = podmanDateTime.ReplaceAllString(logMessage, "")
		logMessage = podmanTypeI.ReplaceAllString(logMessage, Green + "INFO" + Reset + " ${1}")

	}
	if logProcessName == "systemd" ||
		logProcessName == "systemd-logind" {
		// systemd ()
		logMessage = systemdTypeI.ReplaceAllString(logMessage, Green + "INFO" + Reset + " ${1}")
		logMessage = systemdTypeF.ReplaceAllString(logMessage, Purple + "FATAL" + Reset + " ${1}")
		logMessage = systemdTypeE.ReplaceAllString(logMessage, Red + "ERROR" + Reset + " ${1}")

	}
	if logProcessName == "etcd" {
		logMessage = etcdTypeW.ReplaceAllString(logMessage, Cyan + "WARNING" + Reset + " ${1}")
	}
	if logProcessName == "dhclient" {
		logMessage = dhclientTypeI.ReplaceAllString(logMessage, Green + "INFO" + Reset + " ${1}")
	}
	if logProcessName == "NetworkManager" {
		logMessage = networkManagerTypeI.ReplaceAllString(logMessage, Green + "INFO" + Reset + " ${1}")

	}
	if logProcessName == "hyperkube" ||
		logProcessName == "atomic-openshift-master-api" ||
		logProcessName == "atomic-openshift-node" ||
		logProcessName == "machine-config-daemon" {
		logMessage = hyperkubeDateTime.ReplaceAllString(logMessage, "")

		// hyperkube (remove un-needed information from informational messages (rcernin))
		logMessage = hyperkubeInfoFilter.ReplaceAllString(logMessage, "${1}${2}${3}")
		// hyperkube (replace IWEF with INFO/WARN/ERR/FATAL)
		logMessage = hyperkubeTypeI.ReplaceAllString(logMessage, Green + "INFO" + Reset + " ")
		logMessage = hyperkubeTypeW.ReplaceAllString(logMessage, Cyan + "WARNING" + Reset + " ")
		logMessage = hyperkubeTypeE.ReplaceAllString(logMessage, Red + "ERROR" + Reset + " ")
		logMessage = hyperkubeTypeF.ReplaceAllString(logMessage, Purple + "FATAL" + Reset + " ")
		logMessage = hyperkubeTypeIn.ReplaceAllString(logMessage, Green + "INFO" + Reset + " ${1}")
	}

	if podLogs {
		// pod logs (replace IWEF with INFO/WARN/ERR/FATAL)
		logMessage = hyperkubeDateTime.ReplaceAllString(logMessage, "")
		if podLogsProcessName.MatchString(logMessage) {
			logProcessName = podLogsProcessName.ReplaceAllString(logMessage, "${1}")
			logMessage = podLogsRemoveProcessName.ReplaceAllString(logMessage, "")
		} else {
			logProcessName = ""
		}
		logMessage = hyperkubeTypeI.ReplaceAllString(logMessage, Green + "INFO" + Reset + " ")
		logMessage = hyperkubeTypeW.ReplaceAllString(logMessage, Cyan + "WARNING" + Reset + " ")
		logMessage = hyperkubeTypeE.ReplaceAllString(logMessage, Red + "ERROR" + Reset + " ")
		logMessage = hyperkubeTypeF.ReplaceAllString(logMessage, Purple + "FATAL" + Reset + " ")
	}

	if priority == 5 {

	} else if priority == 4 {
		if debugMessage.MatchString(logMessage) {
			return
		}
		// priority 3 means warning, do not show info and debug messages
	} else if priority == 3 {
		if informationalMessage.MatchString(logMessage) || debugMessage.MatchString(logMessage) {
			return
		}
		// priority 2 means error, do not show warning, info and debug messages
	} else if priority == 2 {
		if ! (fatalMessage.MatchString(logMessage) || errorMessage.MatchString(logMessage)) {
			return
		}
		// priority 1 means fatal, do not show error, warning, info and debug messages
	} else if priority == 1 {
		if ! fatalMessage.MatchString(logMessage) {
			return
		}
	}

	logSlice := strings.SplitN(logMessage, " ",2)
	if len(logSlice) >= 2 {
		if processNameCompiled.MatchString(logProcessName) &&
			filterCompiled.MatchString(logSlice[1]) {
			fmt.Println(Blue + logDate + Reset + " " + Yellow + logProcessName + Reset + " " + logMessage)
		} else {
			return
		}
	} else {
		if processNameCompiled.MatchString(logProcessName) &&
			filterCompiled.MatchString(logSlice[0]) {
			fmt.Println(Blue + logDate + Reset + " " + Yellow + logProcessName + Reset + " " + logMessage)
		} else {
			return
		}
	}

}