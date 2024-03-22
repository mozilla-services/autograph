// +build gofuzz

package mar

// Fuzz is a fuzzer for the MAR decoder
func Fuzz(data []byte) int {
	var marFile File
	if err := Unmarshal(data, &marFile); err != nil {
		return 0
	}
	return 1
}
