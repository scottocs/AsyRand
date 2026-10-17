package grandline

import "fmt"

func roundKey(epoch uint64) string {
	return fmt.Sprintf("epoch:%d", epoch)
}
