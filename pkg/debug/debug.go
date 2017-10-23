package debug

import (
	"encoding/json"
	"fmt"
)

// PrettyPrint tries to pretty-print a value, falling-back to 'fmt.Sprintf'.
func PrettyPrint(v interface{}) string {
	res, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(res)
}
