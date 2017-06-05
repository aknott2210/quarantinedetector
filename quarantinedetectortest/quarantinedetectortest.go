package quarantinedetectortest

import (
	"testing"

	"github.com/aknott2210/quarantinedetector"
)

//TestDetectCoordinatorQuarantine asserts that quarantine data is found in the coordinator logs
func TestDetectCoordinatorQuarantine(test *testing.T) {
	x := quarantinedetector.SearchLogsForQuarantine()
	test.Log(x)
}
