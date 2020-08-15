package helpers

import (
	"bufio"
	"fmt"
	"regexp"
)

var (
	base = `^(?P<Date>(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+[0-9]+` +
		`\s+[0-9]+:[0-9]+:[0-9]+)` +
		`\s+(?P<Hostname>[0-9A-Za-z\.\-]*)` +
		`\s+(?P<ProcessName>[0-9A-Za-z\.\-]*)` +
		`(\[)?` +
		`(?P<ProcessPID>[0-9]+)?` +
		`(\])?:`

	generic = `^(?P<Date>(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+[0-9]+` +
		`\s+[0-9]+:[0-9]+:[0-9]+)` +
		`\s+(?P<Hostname>[0-9A-Za-z\.\-]*)` +
		`\s+(?P<ProcessName>[0-9A-Za-z\.\-]*)` +
		`(\[)?` +
		`(?P<ProcessPID>[0-9]+)?` +
		`(\])?:` +
		`\s+(?P<Message>.*)`


	podman = base + `\s+(?P<MessageDate>[0-9]+-[0-9]+-[0-9]+\s+[0-9]+:[0-9]+:[0-9]+\.[0-9]+\s+[+-][0-9]+\s+UTC)` +
		// m=+0.081148367
		`\s+m=[+-][0-9]+\.[0-9]+` +
		// container create ba831 (image=quay.io, name=competent_ritchie)
		`\s+(?P<Message>([A-Za-z]+\s+create\s+([0-9A-Za-z]+)?(.*)?)|` +
		// container init, start, attach, died, remove ba831
		`([A-Za-z]+\s+(init|start|attach|died|remove)\s+([0-9A-Za-z]+)?)|` +
		// image pull
		`([A-Za-z]+\s+[A-Za-z]+)?|` +
		`(.*))?`

	atomicOpenshiftMasterApi = base + `\s+[A-Z]` +
		// 0805 17:54:15.628339
		`([0-9]+\s+[0-9]+:[0-9]+:[0-9]+\.[0-9]+)` +
		`\s+([0-9]+)` +
		// panics.go:76]
		`\s+(?P<Message>[A-Za-z\.]+:[0-9]+\].*)`
)

func parser(w *bufio.Writer, s, processName, parserName, filter string){
	var processNameCompiled = regexp.MustCompile(processName)
	var filterCompiled = regexp.MustCompile(filter)

	m := parseLine(parserName, s)
	if processNameCompiled.MatchString(m["ProcessName"]) &&
		filterCompiled.MatchString(m["Message"]) {
		fmt.Fprintln(w, Blue + m["Date"] + Reset + " " + Yellow + m["ProcessName"] + Reset + " " + m["Message"])
		w.Flush()
	}
	wg.Done()
}

func parseLine(parserName, l string) (makeMap map[string]string) {
	var parserNameCompiled = regexp.Regexp{}
	if parserName == "generic" {
		parserNameCompiled = *regexp.MustCompile(generic)
	} else if parserName == "podman" {
		parserNameCompiled = *regexp.MustCompile(podman)
	} else if parserName == "atomic-openshift-master-api" {
		parserNameCompiled = *regexp.MustCompile(atomicOpenshiftMasterApi)
	}

	match := parserNameCompiled.FindStringSubmatch(l)
	makeMap = make(map[string]string)
	for i, name := range parserNameCompiled.SubexpNames() {
		if i > 0 && i <= len(match) {
			makeMap[name] = match[i]
		}
	}
	return
}
