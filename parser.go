package whois

import (
	"regexp"
	"strings"
)

func regex(expression string, str string) []string {
	var retval []string
	re := regexp.MustCompile(expression).FindAllStringSubmatch(str, -1)
	if len(re) > 0 {
		for _, val := range re {
			retval = append(retval, strings.TrimSpace(val[1]))
		}
	} else {
		retval = append(retval, "")
	}

	return retval
}
