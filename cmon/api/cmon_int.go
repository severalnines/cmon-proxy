package api

import (
	"encoding/json"
	"strconv"
	"strings"
)

type CmonInt int64

func (cmonInt *CmonInt) UnmarshalJSON(b []byte) error {
	if b[0] != '"' {
		return json.Unmarshal(b, (*int64)(cmonInt))
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	i, err := strconv.Atoi(strings.Trim(s, "\r\n\t '\""))
	if err != nil {
		return err
	}
	*cmonInt = CmonInt(i)
	return nil
}
