package mozlogrus

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

var hostname string
var pid int

func init() {
	var err error
	hostname, err = os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	pid = os.Getpid()
}

// Enable sets stdout with idiotmatic mozlog formatting
func Enable(loggerName string) {
	EnableFormatter(&MozLogFormatter{LoggerName: loggerName, Type: "app.log"})
}

// EnableFormatter sets stdout logging with a custom MozLogFormatter
func EnableFormatter(m *MozLogFormatter) {
	logrus.SetFormatter(m)
	logrus.SetOutput(os.Stdout)
}

type MozLogFormatter struct {
	LoggerName string
	Type       string
}

func (m *MozLogFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	t := entry.Time.UTC()
	appLog := &appLog{
		Timestamp:  t.UnixNano(),
		Time:       t.Format(time.RFC3339),
		Type:       m.Type,
		Logger:     m.LoggerName,
		Hostname:   hostname,
		EnvVersion: "2.0",
		Pid:        pid,
		Severity:   toSyslogSeverity(entry.Level),
	}

	// set a default type when it is empty
	if appLog.Type == "" {
		appLog.Type = "app.log"
	}

	// make a copy of entry.Data to prevent side effects
	// when altering "msg" and error types
	data := make(logrus.Fields, len(entry.Data)+1)
	for k, v := range entry.Data {
		switch v := v.(type) {
		case error:
			data[k] = v.Error()
		default:
			data[k] = v
		}
	}

	// prevent losing "msg" when we overwrite it with entry.Message
	if _, ok := data["msg"]; ok {
		data["fields.msg"] = data["msg"]
	}

	data["msg"] = entry.Message
	appLog.Fields = data

	serialized, err := json.Marshal(appLog)
	if err != nil {
		return nil, fmt.Errorf("Failed to marshal appLog to JSON, %v", err)
	}
	return append(serialized, '\n'), nil
}

// toSyslogSeverity converts logrus log levels to syslog ones
func toSyslogSeverity(l logrus.Level) int {
	switch l {
	case logrus.PanicLevel:
		return 1
	case logrus.FatalLevel:
		return 2
	case logrus.ErrorLevel:
		return 3
	case logrus.WarnLevel:
		return 4
	case logrus.InfoLevel:
		return 6
	case logrus.DebugLevel:
		return 7
	default:
		return 0
	}
}
