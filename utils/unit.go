package utils

import "fmt"

func ByteUnit(n uint64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	index := 0
	remain := uint64(0)

	for n >= 1024 {
		remain = (n & 0x03ff)
		n = (n >> 10)
		index += 1

		if index == len(units)-1 {
			break
		}
	}

	remain = (10 * remain) / 1024
	if remain > 0 {
		return fmt.Sprintf("%v.%v%v", n, remain, units[index])
	}
	return fmt.Sprintf("%v%v", n, units[index])
}
