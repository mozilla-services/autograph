package main

import (
	"fmt"
	"time"

	"net/http"

	"github.com/DataDog/datadog-go/statsd"
	log "github.com/sirupsen/logrus"
)

func loadStatsd(conf configuration) (*statsd.Client, error) {
	statsdClient, err := statsd.NewBuffered(conf.Statsd.Addr, conf.Statsd.Buflen)
	if err != nil {
		return nil, fmt.Errorf("error constructing statsdClient: %w", err)
	}
	statsdClient.Namespace = conf.Statsd.Namespace

	return statsdClient, nil
}

func (a *autographer) addStats(conf configuration) (err error) {
	a.stats, err = loadStatsd(conf)
	log.Infof("Statsd enabled at %s with namespace %s", conf.Statsd.Addr, conf.Statsd.Namespace)
	return err
}

// Send statsd success request
func (a *autographer) statsWriteSuccess(r *http.Request, key string) {
	if a.stats != nil {
		starttime := getRequestStartTime(r)
		sendStatsErr := a.stats.Timing(key, time.Since(starttime), nil, 1.0)
		if sendStatsErr != nil {
			log.Warnf("Error sending statsd on success %s: %s", key, sendStatsErr)
		}
	}
}
