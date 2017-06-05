package quarantinedetectortest

import (
	"testing"

	"github.com/aknott2210/quarantinedetector"
)

func TestTestDetectCoordinatorQuarantine(t *testing.T) {
	x := quarantinedetector.SearchLogsForQuarantine()
	t.Log(x)
}
