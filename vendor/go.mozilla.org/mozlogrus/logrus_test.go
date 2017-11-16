package mozlogrus

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func init() {
	// set the global hostname / pid to make it easier to match
	hostname = "test-hostname"
	pid = 1
}

func newLogger(l *MozLogFormatter) (*logrus.Logger, *bytes.Buffer) {
	buf := new(bytes.Buffer)
	logger := logrus.New()
	logger.Out = buf
	logger.Formatter = l
	return logger, buf
}

func TestMozLogFormatter(t *testing.T) {
	assert := assert.New(t)

	logger, buf := newLogger(&MozLogFormatter{"Logger", "test.log"})
	fields := logrus.Fields{
		"a":   "string",
		"b":   int(10),
		"c":   float64(3.14),
		"d":   errors.New("err test"),
		"msg": "old message",
	}
	logger.WithFields(fields).Info("new message")

	a := new(appLog)

	if err := json.Unmarshal(buf.Bytes(), &a); !assert.NoError(err) {
		return
	}

	assert.Equal(toSyslogSeverity(logrus.InfoLevel), a.Severity)
	assert.Equal("Logger", a.Logger)
	assert.Equal("test.log", a.Type)

	if v, ok := a.Fields["a"].(string); assert.True(ok) {
		assert.Equal("string", v)
	}

	// json doesn't have an int type so it's converted to float64
	if v, ok := a.Fields["b"].(float64); assert.True(ok) {
		assert.Equal(10.0, v)
	}
	if v, ok := a.Fields["c"].(float64); assert.True(ok) {
		assert.Equal(3.14, v)
	}

	// our error is now converted to a string
	if v, ok := a.Fields["d"].(string); assert.True(ok) {
		assert.Equal("err test", v)
	}

	// make sure "msg" was copied to field.msg
	if _, ok := a.Fields["fields.msg"]; assert.True(ok, "fields.msg missing") {
		if v, ok := a.Fields["fields.msg"].(string); assert.True(ok) {
			assert.Equal("old message", v)
		}
	}

	if _, ok := a.Fields["msg"]; assert.True(ok, "msg missing") {
		if v, ok := a.Fields["msg"].(string); assert.True(ok) {
			assert.Equal("new message", v)
		}
	}
}

func BenchmarkMozLogFormatter(b *testing.B) {

	entry := logrus.WithFields(logrus.Fields{
		"agent":     "benchmark agent",
		"errno":     0,
		"method":    "GET",
		"path":      "/so/fassst",
		"req_sz":    0,
		"res_sz":    1024,
		"t":         20,
		"uid":       "123456",
		"fxa_uid":   "123456",
		"device_id": "7654321",
		"msg":       "i will be replaced",
	})

	formatter := &MozLogFormatter{
		LoggerName: "benchmarker",
		Type:       "test.log",
	}

	for i := 0; i < b.N; i++ {
		formatter.Format(entry)
	}

}
