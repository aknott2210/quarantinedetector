package quarantinedetector

import (
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strconv"

	"github.com/kardianos/osext"
)

//LogDetails has important information about any log where a quarantine was detected
type LogDetails struct {
	path string
	date string
	host string
}

var services = []string{"coordinatorNode_", "receiverNode_"}

const dateRegExPattern = "[0-9]+-[0-9]+-[0-9]+ [0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}\\,[0-9]+"
const hostRegExPattern = "\\[akka.tcp://ebicluster@[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}:[0-9]+\\]"
const quarantineMsgRegExPattern = dateRegExPattern + " WARN  \\[Remoting\\] Association to \\[akka.tcp://ebicluster@[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}:[0-9]+\\]"

func exists(path string) bool {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return true
}

func searchLogFile(logDetails *[]LogDetails, file *os.File, path string) {
	logBytes, err := ioutil.ReadAll(file)
	if err != nil {
		log.Println(err)
	}
	matchLogForQuarantine(logDetails, string(logBytes[:]), path)
}

func matchLogForQuarantine(logDetails *[]LogDetails, log string, path string) {
	quarantineRegEx := regexp.MustCompile(quarantineMsgRegExPattern)
	hostRegEx := regexp.MustCompile(hostRegExPattern)
	dateRegEx := regexp.MustCompile(dateRegExPattern)
	quarantineMatches := quarantineRegEx.FindAllStringSubmatch(log, -1)
	for r := range quarantineMatches {
		for _, quarantineMatch := range quarantineMatches[r] {
			dateMatch := dateRegEx.FindStringSubmatch(quarantineMatch)[0]
			hostMatch := hostRegEx.FindStringSubmatch(quarantineMatch)[0]
			*logDetails = append(*logDetails, LogDetails{path, dateMatch, hostMatch})
		}
	}
}

//SearchLogsForQuarantine searches all coordinator and receiver logs in
//the share for quarantine keywords
func SearchLogsForQuarantine() []LogDetails {
	index := 0
	logDetails := make([]LogDetails, 0)
	for _, service := range services {
		searchLogForQuarantine(&logDetails, service, index)
	}
	return logDetails
}

func searchLogForQuarantine(logDetails *[]LogDetails, service string, index int) {
	exist := true
	folderPath, err := osext.ExecutableFolder()
	if err != nil {
		log.Fatal(err)
	}

	for exist {
		path := folderPath + "\\nodes\\" + service + strconv.Itoa(index) + "\\logs\\cluster.log"
		exist = exists(path)
		if exist {
			appendLogDetails(logDetails, path)
			index++
		} else {
			index = 0
		}
	}
}

func appendLogDetails(logDetails *[]LogDetails, path string) {
	file, err := os.Open(path)
	if err != nil {
		log.Println(err)
	}
	defer file.Close()
	searchLogFile(logDetails, file, path)
}
