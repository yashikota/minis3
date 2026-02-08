package handler

import (
	"encoding/xml"
	"io"
)

var (
	readAllFn    = io.ReadAll
	xmlMarshalFn = xml.Marshal
)
