package mozlogrus

import (
	"encoding/json"

	"github.com/sirupsen/logrus"
)

// appLog implements Mozilla logging standard
type appLog struct {
	Timestamp  int64
	Time       string
	Type       string
	Logger     string
	Hostname   string `json:",omitempty"`
	EnvVersion string
	Pid        int           `json:",omitempty"`
	Severity   int           `json:",omitempty"`
	Fields     logrus.Fields `json:",omitempty"`
}

// ToJSON converts a logline to JSON
func (a *appLog) ToJSON() ([]byte, error) {
	return json.Marshal(a)
}
