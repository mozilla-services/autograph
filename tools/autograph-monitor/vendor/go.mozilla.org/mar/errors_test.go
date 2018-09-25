package mar

import "testing"

func TestDebugPrint(t *testing.T) {
	debug = "true"
	debugPrint("debug is %s\n", debug)
	debug = "false"
}
