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

func ParseFile(file *os.File, sinceTime, untilTime time.Time, processName, filter string, priority int, analysis, ignoreErrors, showHostname bool) error {
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

	addYear := true
	var analysisDataMap = cmap.New()

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
			ProcessChunk(buf, analysisDataMap, &linesPool, &stringPool, sinceTime, untilTime, processName, filter, priority, analysis, ignoreErrors, showHostname, addYear)
			wg.Done()
		}()
	}
	wg.Wait()
	if analysis {
		fmt.Printf(Red + "\n\t\tANALYSIS SECTION\n" + Reset)
		for _, name := range analysisDataMap.Keys() {
			fmt.Printf("\n")
			fmt.Println(Purple + "Hostname:" + Reset + " " + Cyan + name + Reset)
			if tmp, ok := analysisDataMap.Get(name); ok {
				nested := tmp.(cmap.ConcurrentMap)
				for _, name := range nested.Keys() {
					fmt.Printf("\n")
					fmt.Println(Purple + "    Message:" + Reset + " " + name)
					if tmp, ok := nested.Get(name); ok {
						nested := tmp.(cmap.ConcurrentMap)
						if tmp, ok := nested.Get("Process Name"); ok {
							fmt.Printf(Purple + "    Process Name" + ":" + Reset + " ")
							fmt.Println(tmp.(string))
						}
						if tmp, ok := nested.Get("First Appearance"); ok {
							fmt.Printf(Purple + "    First Appearance" + ":" + Reset + " ")
							fmt.Println(tmp.(string))
						}
						if tmp, ok := nested.Get("Last Appearance"); ok {
							fmt.Printf(Purple + "    Last Appearance" + ":" + Reset + " ")
							fmt.Println(tmp.(string))
						}
						if tmp, ok := nested.Get("Count"); ok {
							fmt.Printf(Purple + "    Count" + ":" + Reset + " ")
							fmt.Println(tmp.(int))
						}
					}
				}
			}
		}
		fmt.Printf("\n")
	}
	return nil
}

func ProcessChunk(chunk []byte, analysisDataMap cmap.ConcurrentMap, linesPool, stringPool *sync.Pool, sinceTime, untilTime time.Time, processName, filter string, priority int, analysis, ignoreErrors, showHostname, addYear bool) {
	var logCreationTimeString string
	var logLine *regexp.Regexp
	var logCreationTime time.Time
	var err error
	var podLogs bool

	logs := stringPool.Get().(string)
	logs = string(chunk)

	linesPool.Put(chunk)
	logsSlice := strings.Split(logs, "\n")
	stringPool.Put(logs)

	chunkSize := 50000
	n := len(logsSlice)
	noOfThread := n / chunkSize

	if n%chunkSize != 0 {
		noOfThread++
	}

	makeMap := cmap.New()

	for i := 0; i < (noOfThread); i++ {
		for i := i * chunkSize; i < int(math.Min(float64((i+1)*chunkSize), float64(len(logsSlice)))); i++ {
			text := logsSlice[i]
			if len(text) == 0 {
				continue
			}
			podsLogLine := regexp.MustCompile(`^(?P<Date>[0-9]+-[0-9]+-[0-9]+T[0-9]+:[0-9]+:[0-9]+\.[0-9]+Z)\s+` +
				`([0-9]+-[0-9]+-[0-9]+\s[0-9]+:[0-9]+:[0-9]+.[0-9]+\s+)?` +
				`(?P<Message>.*)`)
			systemLogLine := regexp.MustCompile(`^(?P<Date>(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+[0-9]+` +
				`\s+[0-9]+:[0-9]+:[0-9]+)` +
				`\s+(?P<Hostname>[0-9A-Za-z\.\-]*)` +
				`\s+(?P<ProcessName>[0-9A-Za-z\._()/\-]*)` +
				`(\[)?` +
				`(?P<ProcessPID>[0-9]+)?` +
				`(\])?:` +
				`\s+(?P<Message>.*)`)

			if systemLogLine.MatchString(text) {
				logLine = systemLogLine

				match := logLine.FindStringSubmatch(text)
				for i, name := range logLine.SubexpNames() {
					if i > 0 && i <= len(match) {
						makeMap.Set(name, match[i])
					}
				}
			} else if podsLogLine.MatchString(text) {
				podLogs = true
				logLine = podsLogLine
				if addYear {
					year := time.Now().UTC().Year()
					sinceTime = sinceTime.AddDate(year, 0, 0)
					untilTime = untilTime.AddDate(year, 0, 0)
					addYear = false
				}

				match := logLine.FindStringSubmatch(text)

				for i, name := range logLine.SubexpNames() {
					if i > 0 && i <= len(match) {
						makeMap.Set(name, match[i])
					}
				}
			} else {
				if ignoreErrors == false {
					fmt.Println(Red + "Unable to parse text:\n " + text + Reset)
				}
			}

			if tmp, ok := makeMap.Get("Date"); ok {
				logCreationTimeString = tmp.(string)
			}

			if podLogs == true {
				logCreationTime, err = time.Parse("2006-01-02T15:04:05.999999999Z", logCreationTimeString)
				if err != nil {
					if ignoreErrors == false {
						fmt.Println(Red + "Unable to parse date and time format:\n " + text + Reset)
					}
				}
			} else {
				logCreationTime, err = time.Parse("Jan 2 15:04:05", logCreationTimeString)
				if err != nil {
					if ignoreErrors == false {
						fmt.Println(Red + "Unable to parse date and time format:\n " + text + Reset)
					}
				}
			}
			if logCreationTime.After(sinceTime) && logCreationTime.Before(untilTime) {
				FilterLog(makeMap, analysisDataMap, processName, filter, priority, analysis, showHostname, podLogs)
			}
		}
	}
	logsSlice = nil
}

func FilterLog(makeMap, analysisDataMap cmap.ConcurrentMap, processName, filter string, priority int, analysis, showHostname, podLogs bool) {
	var logDate, logProcessName, logHostname, logMessage string
	var processNameCompiled = regexp.MustCompile(processName)
	var filterCompiled = regexp.MustCompile(filter)
	var lastAppearanceTime time.Time
	var firstAppearanceTime time.Time
	var logDateTime time.Time

	if tmp, ok := makeMap.Get("Date"); ok {
		logDate = tmp.(string)
	}
	if tmp, ok := makeMap.Get("Hostname"); ok {
		logHostname = tmp.(string)
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
	// crio
	crioDateTime := regexp.MustCompile(`time="[0-9]+-[0-9]+-[0-9]+\s+[0-9]+:[0-9]+:[0-9]+(\.[0-9]+)?Z"\s+`)
	// openstack (remove date)
	//  2020-08-25 06:42:44.805 28
	openstackDateTime := regexp.MustCompile(`[0-9]+-[0-9]+-[0-9]+\s+[0-9]+:[0-9]+:[0-9]+(\.[0-9]+)?\s+[0-9]+\s+`)
	openstackTypeI := regexp.MustCompile(`^(INFO)`)
	openstackTypeE := regexp.MustCompile(`^(ERROR)`)
	openstackTypeW := regexp.MustCompile(`^(WARNING)`)
	openstackTypeD := regexp.MustCompile(`^(DEBUG)`)

	// podlogs extra date
	podlogsDateTime := regexp.MustCompile(`^([0-9]+-[0-9]+-[0-9]+T[0-9]+:[0-9]+:[0-9]+(\.[0-9]+)?Z\|[0-9]+\|)`)
	podlogsTypeI := regexp.MustCompile(`^(.*\|INFO\|)`)
	podlogsTypeW := regexp.MustCompile(`^(.*\|WARN\|)`)

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
	hyperkubeTypeI := regexp.MustCompile(`^I\s+|^\[INFO]\s+|^\[\+]`)
	hyperkubeTypeW := regexp.MustCompile(`^W\s+|^\[-]`)
	hyperkubeTypeE := regexp.MustCompile(`^E\s+|^Error:\s+`)
	hyperkubeTypeF := regexp.MustCompile(`^F\s+|^C\s+`)
	hyperkubeTypeIn := regexp.MustCompile(`^(,StartedAt|, Header)`)

	// systemd (replace info, error messages)
	systemdTypeI := regexp.MustCompile(`^(Started|Starting|Created|Stopping|Stopped|Removed|New session|.*Consumed|` +
		`Configuration file.*Proceeding anyway.)`)
	systemdTypeF := regexp.MustCompile(`^(Failed)`)
	systemdTypeE := regexp.MustCompile(`^(.*Main process exited|.*Failed with result|.*.service entered failed state.|` +
		`.*service\sfailed.|.*.service: main process exited.*)`)
	systemdTypeW := regexp.MustCompile(`^(.*timed out. Killing.)`)
	// dhclient (replace info, error message)
	dhclientTypeI := regexp.MustCompile(`^(DHCPREQUEST|DHCPACK|bound to)`)

	// dnsmasq
	dnsmasqTypeI := regexp.MustCompile(`^(using nameserver|setting upstream servers)`)
	// crond
	crondTypeI := regexp.MustCompile(`^(PAM adding)`)
	crondTypeW := regexp.MustCompile(`^(PAM unable to dlopen)`)
	// auditd
	auditdTypeW := regexp.MustCompile(`^(dispatch err \(pipe full\) event lost)`)
	auditdTypeE := regexp.MustCompile(`^(dispatch error reporting limit reached)`)
	auditdTypeI := regexp.MustCompile(`^(Audit daemon rotating log files)`)
	// etcd
	etcdTypeW := regexp.MustCompile(`^(health check for peer.*connect:.*connection refused)`)
	// sssd_be
	sssdbeTypeI := regexp.MustCompile(`^(GSSAPI client step)`)
	// sshd
	sshdTypeI := regexp.MustCompile(`^(Connection from|Close session|` +
		`Starting session|Did not receive identification|Postponed publickey|` +
		`Accepted publickey|Received disconnect|Disconnected|User child is on|pam_unix)`)
	// podman
	podmanTypeI := regexp.MustCompile(`^(container)`)
	// crio
	crioTypeI := regexp.MustCompile(`^(level=info)`)
	crioTypeE := regexp.MustCompile(`^(level=error)`)
	crioTypeW := regexp.MustCompile(`^(level=warning)`)
	// auoms
	auomsTypeI := regexp.MustCompile(`^(AuditRulesMonitor: Found desired|AuditRulesMonitor: augenrules succeeded|` +
		`AuditRulesMonitor: augenrules appears to be in-use|Output.*Connecting|Output.*Connected)`)
	auomsTypeE := regexp.MustCompile(`^(Output.*Connection lost)`)
	// oci-systemd-hook
	ociSystemHookTypeD := regexp.MustCompile(`^(.*<debug>.*)`)
	// anacron
	anacronTypeI := regexp.MustCompile(`^(Anacron started|Will run job|Jobs will be executed|Normal exit|Job.*terminated|Job.*started)`)
	// kernel
	kernelTypeI := regexp.MustCompile(`^(XFS.*Ending clean mount|XFS.*Mounting V5 Filesystem|XFS.* Unmounting Filesystem|` +
		`SELinux: mount invalid.|device.*entered promiscuous mode|IN=)`)
	// podlog process
	podLogsProcessName := regexp.MustCompile(`[A-Z]+\s+\|\s+([A-Za-z0-9\-/._]+):.*`)
	podLogsRemoveProcessName := regexp.MustCompile(`\s+\|\s+([A-Za-z0-9\-/._]+):`)
	// stunel
	stunnelTypeE := regexp.MustCompile(`^(LOG3.*SSL_accept: Peer suddenly disconnected)`)
	// NetworkManager
	networkManagerTypeI := regexp.MustCompile(`^(<info>)`)
	// mutlipathd
	multipathdTypeI := regexp.MustCompile(`^(dm.*remove map \(uevent\)|dm.*devmap not registered, can't remove)`)
	// global messages
	informationalMessage := regexp.MustCompile(`^\[32mINFO`)
	// warningMessage := regexp.MustCompile(`^WARNING`)
	errorMessage := regexp.MustCompile(`^\[31mERROR`)
	fatalMessage := regexp.MustCompile(`^\[35mFATAL`)
	debugMessage := regexp.MustCompile(`^\[37mDEBUG`)

	// Filter out Date + Time+stamp on each line
	// because we keep the system Date + Time+stamp
	if logProcessName == "podman" {
		logMessage = podmanDateTime.ReplaceAllString(logMessage, "")
		logMessage = podmanTypeI.ReplaceAllString(logMessage, Green+"INFO"+Reset+" ${1}")
	}
	if logProcessName == "crio" {
		logMessage = crioDateTime.ReplaceAllString(logMessage, "")
		logMessage = crioTypeI.ReplaceAllString(logMessage, Green+"INFO"+Reset+" ")
		logMessage = crioTypeW.ReplaceAllString(logMessage, Cyan+"WARNING"+Reset+" ")
		logMessage = crioTypeE.ReplaceAllString(logMessage, Red+"ERROR"+Reset+" ")
	}
	if logProcessName == "keystone-admin" ||
		logProcessName == "keystone-public" ||
		logProcessName == "glance-api" ||
		logProcessName == "glance-manage" ||
		logProcessName == "cinder-api" ||
		logProcessName == "neutron-server" ||
		logProcessName == "nova-api" ||
		logProcessName == "nova-api-metadata" ||
		logProcessName == "nova-conductor" ||
		logProcessName == "nova-consoleauth" ||
		logProcessName == "nova-manage" ||
		logProcessName == "nova-novncproxy" ||
		logProcessName == "nova-scheduler" {
		logMessage = openstackDateTime.ReplaceAllString(logMessage, "")
		logMessage = openstackTypeI.ReplaceAllString(logMessage, Green+"INFO"+Reset+" ")
		logMessage = openstackTypeE.ReplaceAllString(logMessage, Red+"ERROR"+Reset+" ")
		logMessage = openstackTypeW.ReplaceAllString(logMessage, Cyan+"WARNING"+Reset+" ")
		logMessage = openstackTypeD.ReplaceAllString(logMessage, Gray+"DEBUG"+Reset+" ")
	}
	if podLogs {
		logMessage = podlogsDateTime.ReplaceAllString(logMessage, "")
		logMessage = podlogsTypeI.ReplaceAllString(logMessage, Green+"INFO"+Reset+" ${1}")
		logMessage = podlogsTypeW.ReplaceAllString(logMessage, Cyan+"WARNING"+Reset+" ${1}")
	}
	if logProcessName == "systemd" ||
		logProcessName == "systemd-logind" {
		// systemd ()
		logMessage = systemdTypeI.ReplaceAllString(logMessage, Green+"INFO"+Reset+" ${1}")
		logMessage = systemdTypeF.ReplaceAllString(logMessage, Purple+"FATAL"+Reset+" ${1}")
		logMessage = systemdTypeE.ReplaceAllString(logMessage, Red+"ERROR"+Reset+" ${1}")
		logMessage = systemdTypeW.ReplaceAllString(logMessage, Cyan+"WARNING"+Reset+" ${1}")
	}
	if logProcessName == "etcd" {
		logMessage = etcdTypeW.ReplaceAllString(logMessage, Cyan+"WARNING"+Reset+" ${1}")
	}
	if logProcessName == "oci-systemd-hook" {
		logMessage = ociSystemHookTypeD.ReplaceAllString(logMessage, Gray+"DEBUG"+Reset+" ${1}")
	}
	if logProcessName == "auditd" {
		logMessage = auditdTypeW.ReplaceAllString(logMessage, Cyan+"WARNING"+Reset+" ${1}")
		logMessage = auditdTypeE.ReplaceAllString(logMessage, Red+"ERROR"+Reset+" ${1}")
		logMessage = auditdTypeI.ReplaceAllString(logMessage, Green+"INFO"+Reset+" ${1}")
	}
	if logProcessName == "dockerd-current" {
		logMessage = podlogsDateTime.ReplaceAllString(logMessage, "")
		logMessage = podlogsTypeI.ReplaceAllString(logMessage, Green+"INFO"+Reset+" ${1}")
		logMessage = podlogsTypeW.ReplaceAllString(logMessage, Cyan+"WARNING"+Reset+" ${1}")
	}
	if logProcessName == "dhclient" {
		logMessage = dhclientTypeI.ReplaceAllString(logMessage, Green+"INFO"+Reset+" ${1}")
	}
	if logProcessName == "anacron" {
		logMessage = anacronTypeI.ReplaceAllString(logMessage, Green+"INFO"+Reset+" ${1}")
	}
	if logProcessName == "stunnel" {
		logMessage = stunnelTypeE.ReplaceAllString(logMessage, Red+"ERROR"+Reset+" ${1}")
	}
	if logProcessName == "auoms" {
		logMessage = auomsTypeI.ReplaceAllString(logMessage, Green+"INFO"+Reset+" ${1}")
		logMessage = auomsTypeE.ReplaceAllString(logMessage, Red+"ERROR"+Reset+" ${1}")
	}
	if logProcessName == "NetworkManager" {
		logMessage = networkManagerTypeI.ReplaceAllString(logMessage, Green+"INFO"+Reset+" ${1}")

	}
	if logProcessName == "multipathd" {
		logMessage = multipathdTypeI.ReplaceAllString(logMessage, Green+"INFO"+Reset+" ${1}")
	}
	if logProcessName == "crond" {
		logMessage = crondTypeI.ReplaceAllString(logMessage, Green+"INFO"+Reset+" ${1}")
		logMessage = crondTypeW.ReplaceAllString(logMessage, Cyan+"WARNING"+Reset+" ${1}")
	}
	if logProcessName == "kernel" {
		logMessage = kernelTypeI.ReplaceAllString(logMessage, Green+"INFO"+Reset+" ${1}")
	}
	if logProcessName == "sshd" {
		logMessage = sshdTypeI.ReplaceAllString(logMessage, Green+"INFO"+Reset+" ${1}")
	}
	if logProcessName == "sssd_be" {
		logMessage = sssdbeTypeI.ReplaceAllString(logMessage, Green+"INFO"+Reset+" ${1}")
	}
	if logProcessName == "dnsmasq" {
		logMessage = dnsmasqTypeI.ReplaceAllString(logMessage, Green+"INFO"+Reset+" ${1}")
	}
	if logProcessName == "hyperkube" ||
		logProcessName == "atomic-openshift-master-api" ||
		logProcessName == "atomic-openshift-node" ||
		logProcessName == "machine-config-daemon" {
		logMessage = hyperkubeDateTime.ReplaceAllString(logMessage, "")

		// hyperkube (remove un-needed information from informational messages (rcernin))
		logMessage = hyperkubeInfoFilter.ReplaceAllString(logMessage, "${1}${2}${3}")
		// hyperkube (replace IWEF with INFO/WARN/ERR/FATAL)
		logMessage = hyperkubeTypeI.ReplaceAllString(logMessage, Green+"INFO"+Reset+" ")
		logMessage = hyperkubeTypeW.ReplaceAllString(logMessage, Cyan+"WARNING"+Reset+" ")
		logMessage = hyperkubeTypeE.ReplaceAllString(logMessage, Red+"ERROR"+Reset+" ")
		logMessage = hyperkubeTypeF.ReplaceAllString(logMessage, Purple+"FATAL"+Reset+" ")
		logMessage = hyperkubeTypeIn.ReplaceAllString(logMessage, Green+"INFO"+Reset+" ${1}")
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
		logMessage = hyperkubeTypeI.ReplaceAllString(logMessage, Green+"INFO"+Reset+" ")
		logMessage = hyperkubeTypeW.ReplaceAllString(logMessage, Cyan+"WARNING"+Reset+" ")
		logMessage = hyperkubeTypeE.ReplaceAllString(logMessage, Red+"ERROR"+Reset+" ")
		logMessage = hyperkubeTypeF.ReplaceAllString(logMessage, Purple+"FATAL"+Reset+" ")
		logMessage = hyperkubeTypeIn.ReplaceAllString(logMessage, Green+"INFO"+Reset+" ${1}")
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
		if !(fatalMessage.MatchString(logMessage) || errorMessage.MatchString(logMessage)) {
			return
		}
		// priority 1 means fatal, do not show error, warning, info and debug messages
	} else if priority == 1 {
		if !fatalMessage.MatchString(logMessage) {
			return
		}
	}
	logSlice := strings.SplitN(logMessage, " ", 2)

	if len(logSlice) >= 2 {
		if processNameCompiled.MatchString(logProcessName) &&
			filterCompiled.MatchString(logSlice[1]) {
			if showHostname {
				fmt.Println(Blue + logDate + Reset + " " + Cyan + logHostname + Reset + " " + Yellow + logProcessName + Reset + " " + logMessage)
			} else {
				fmt.Println(Blue + logDate + Reset + " " + Yellow + logProcessName + Reset + " " + logMessage)
			}
			if analysis {
				if v, ok := analysisDataMap.Get(logHostname); !ok {
					analysisDataMap.Set(logHostname, cmap.New())
					if v, ok := analysisDataMap.Get(logHostname); ok {
						nested := v.(cmap.ConcurrentMap)
						if _, ok := nested.Get(logMessage); !ok {
							nested.Set(logMessage, cmap.New())
							if v, ok := nested.Get(logMessage); ok {
								nested := v.(cmap.ConcurrentMap)
								if _, ok := nested.Get("Count"); !ok {
									// Setting initial count for first message per host
									nested.Set("Count", 1)
								}
								if _, ok := nested.Get("Process Name"); !ok {
									// Setting process name for first message per host
									nested.Set("Process Name", logProcessName)
								}
								if _, ok := nested.Get("First Appearance"); !ok {
									// Setting initial first for first message per host
									nested.Set("First Appearance", logDate)
								}
								if _, ok := nested.Get("Last Appearance"); !ok {
									// Setting initial last for first message per host
									nested.Set("Last Appearance", logDate)
								}
							}
						}
					}
				} else {
					nested := v.(cmap.ConcurrentMap)
					if v, ok := nested.Get(logMessage); !ok {
						nested.Set(logMessage, cmap.New())
						if v, ok := nested.Get(logMessage); ok {
							nested := v.(cmap.ConcurrentMap)
							if _, ok := nested.Get("Count"); !ok {
								// Setting initial count for the rest of the messages
								nested.Set("Count", 1)
							}
							if _, ok := nested.Get("Process Name"); !ok {
								// Setting process name for first message per host
								nested.Set("Process Name", logProcessName)
							}
							if _, ok := nested.Get("First Appearance"); !ok {
								// Setting initial first for the rest of the messages
								nested.Set("First Appearance", logDate)
							}
							if _, ok := nested.Get("Last Appearance"); !ok {
								// Setting initial last for the rest of the messages
								nested.Set("Last Appearance", logDate)
							}
						}
					} else {
						nested := v.(cmap.ConcurrentMap)
						if v, ok := nested.Get("Count"); ok {
							tmp := v.(int)
							nested.Set("Count", tmp+1)
						}
						if v, ok := nested.Get("Last Appearance"); ok {
							lastAppearance := v.(string)
							if podLogs == true {
								lastAppearanceTime, _ = time.Parse("2006-01-02T15:04:05.999999999Z", lastAppearance)
								logDateTime, _ = time.Parse("2006-01-02T15:04:05.999999999Z", logDate)
							} else {
								lastAppearanceTime, _ = time.Parse("Jan 2 15:04:05", lastAppearance)
								logDateTime, _ = time.Parse("Jan 2 15:04:05", logDate)
							}
							if logDateTime.After(lastAppearanceTime) {
								nested.Set("Last Appearance", logDate)
							}
						}
						if v, ok := nested.Get("First Appearance"); ok {
							firstAppearance := v.(string)
							if podLogs == true {
								firstAppearanceTime, _ = time.Parse("2006-01-02T15:04:05.999999999Z", firstAppearance)
								logDateTime, _ = time.Parse("2006-01-02T15:04:05.999999999Z", logDate)
							} else {
								firstAppearanceTime, _ = time.Parse("Jan 2 15:04:05", firstAppearance)
								logDateTime, _ = time.Parse("Jan 2 15:04:05", logDate)
							}
							if logDateTime.Before(firstAppearanceTime) {
								nested.Set("First Appearance", logDate)
							}
						}
					}
				}
			}
		} else {
			return
		}
	} else {
		if processNameCompiled.MatchString(logProcessName) &&
			filterCompiled.MatchString(logSlice[0]) {
			if showHostname {
				fmt.Println(Blue + logDate + Reset + " " + Cyan + logHostname + Reset + " " + Yellow + logProcessName + Reset + " " + logMessage)
			} else {
				fmt.Println(Blue + logDate + Reset + " " + Yellow + logProcessName + Reset + " " + logMessage)
			}
			if analysis {
				if v, ok := analysisDataMap.Get(logHostname); !ok {
					analysisDataMap.Set(logHostname, cmap.New())
					if v, ok := analysisDataMap.Get(logHostname); ok {
						nested := v.(cmap.ConcurrentMap)
						if _, ok := nested.Get(logMessage); !ok {
							nested.Set(logMessage, cmap.New())
							if v, ok := nested.Get(logMessage); ok {
								nested := v.(cmap.ConcurrentMap)
								if _, ok := nested.Get("Count"); !ok {
									// Setting initial count for first message per host
									nested.Set("Count", 1)
								}
								if _, ok := nested.Get("Process Name"); !ok {
									// Setting process name for first message per host
									nested.Set("Process Name", logProcessName)
								}
								if _, ok := nested.Get("First Appearance"); !ok {
									// Setting initial first for first message per host
									nested.Set("First Appearance", logDate)
								}
								if _, ok := nested.Get("Last Appearance"); !ok {
									// Setting initial last for first message per host
									nested.Set("Last Appearance", logDate)
								}
							}
						}
					}
				} else {
					nested := v.(cmap.ConcurrentMap)
					if v, ok := nested.Get(logMessage); !ok {
						nested.Set(logMessage, cmap.New())
						if v, ok := nested.Get(logMessage); ok {
							nested := v.(cmap.ConcurrentMap)
							if _, ok := nested.Get("Count"); !ok {
								// Setting initial count for the rest of the messages
								nested.Set("Count", 1)
							}
							if _, ok := nested.Get("Process Name"); !ok {
								// Setting process name for first message per host
								nested.Set("Process Name", logProcessName)
							}
							if _, ok := nested.Get("First Appearance"); !ok {
								// Setting initial first for the rest of the messages
								nested.Set("First Appearance", logDate)
							}
							if _, ok := nested.Get("Last Appearance"); !ok {
								// Setting initial last for the rest of the messages
								nested.Set("Last Appearance", logDate)
							}
						}
					} else {
						nested := v.(cmap.ConcurrentMap)
						if v, ok := nested.Get("Count"); ok {
							tmp := v.(int)
							nested.Set("Count", tmp+1)
						}
						if v, ok := nested.Get("Last Appearance"); ok {
							lastAppearance := v.(string)
							lastAppearanceTime, _ := time.Parse("Jan 2 15:04:05", lastAppearance)
							logDateTime, _ := time.Parse("Jan 2 15:04:05", logDate)

							if logDateTime.After(lastAppearanceTime) {
								nested.Set("Last Appearance", logDate)
							}
						}
						if v, ok := nested.Get("First Appearance"); ok {
							firstAppearance := v.(string)
							firstAppearanceTime, _ := time.Parse("Jan 2 15:04:05", firstAppearance)
							logDateTime, _ := time.Parse("Jan 2 15:04:05", logDate)

							if logDateTime.Before(firstAppearanceTime) {
								nested.Set("First Appearance", logDate)
							}
						}
					}
				}
			}
		} else {
			return
		}
	}

}
