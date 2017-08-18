package mozlogrus

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"go.mozilla.org/mozlog"

	"github.com/sirupsen/logrus"
)

// Enable enables mozlogrus
func Enable(loggerName string) {
	logrus.SetFormatter(&MozLogFormatter{
		LoggerName: loggerName,
	})

	logrus.SetOutput(os.Stdout)
}

// SetFormatterName the LoggerName for the logrus formatter
func SetFormatterName(name string) {
	logrus.SetFormatter(&MozLogFormatter{
		LoggerName: name,
	})
}

// prefixFieldClashes is from logrus package
func prefixFieldClashes(data logrus.Fields) {
	_, ok := data["msg"]
	if ok {
		data["fields.msg"] = data["msg"]
	}
}

type MozLogFormatter struct {
	LoggerName string
}

func (m *MozLogFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	appLog := &mozlog.AppLog{
		Timestamp:  entry.Time.UTC().UnixNano(),
		Time:       entry.Time.UTC().Format(time.RFC3339),
		Type:       "app.log",
		Logger:     m.LoggerName,
		Hostname:   mozlog.Hostname(),
		EnvVersion: "2.0",
		Pid:        os.Getpid(),
		Severity:   int(entry.Level),
	}

	data := make(logrus.Fields, len(entry.Data)+1)
	for k, v := range entry.Data {
		switch v := v.(type) {
		case error:
			data[k] = v.Error()
		default:
			data[k] = v
		}
	}

	prefixFieldClashes(data)
	data["msg"] = entry.Message

	appLog.Fields = data

	serialized, err := json.Marshal(appLog)
	if err != nil {
		return nil, fmt.Errorf("Failed to mashal fields to JSON, %v", err)
	}
	return append(serialized, '\n'), nil
}
