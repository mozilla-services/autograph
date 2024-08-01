package main

import (
	"fmt"

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

func (a *autographer) addStats(conf configuration) error {
	if conf.Statsd.Addr == "" {
		// a.stats is set to a safe value in newAutographer, so we leave it
		// alone and return.
		log.Infof("Statsd left disabled as no `statsd.addr` was provided in config")
		return nil
	}

	stats, err := loadStatsd(conf)
	if err != nil {
		return err
	}
	a.stats = stats
	log.Infof("Statsd enabled at %s with namespace %s", conf.Statsd.Addr, conf.Statsd.Namespace)
	return nil
}
