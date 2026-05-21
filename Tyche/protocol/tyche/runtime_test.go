package tyche

import (
	"runtime"
	"testing"
)

func TestPrintRuntimeParallelism(t *testing.T) {
	t.Logf("NumCPU=%d GOMAXPROCS=%d", runtime.NumCPU(), runtime.GOMAXPROCS(0))
}
