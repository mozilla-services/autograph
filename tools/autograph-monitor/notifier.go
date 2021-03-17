package main

import (
	"fmt"
	"log"
	"time"

	"github.com/PagerDuty/go-pagerduty"
)

// Notifier is an interface for sending and resolving warning notifications
type Notifier interface {
	// Send writes a message with an id to a notification channel
	Send(id, severity, message string) error
}

// PDEventNotifier updates pagerduty alerts
type PDEventNotifier struct {
	// RoutingKey is the 32 character Integration Key for an
	// integration on a service or on a global ruleset.
	RoutingKey string
	// PayloadSource is the unique location of the affected
	// system, preferably a hostname or FQDN.
	PayloadSource string
	// PayloadComponent is the component of the source machine
	// that is responsible for the event, for example mysql or
	// eth0.
	PayloadComponent string
}

// Send a pagerduty V2 Event using the configured routing key and
// de-dupe key
//
// https://developer.pagerduty.com/docs/events-api-v2/trigger-events/
func (n *PDEventNotifier) Send(dedupeKey, severity, message string) error {
	var (
		err   error
		event *pagerduty.V2Event
	)
	if n == nil {
		return fmt.Errorf("notifier: received nil PDEventNotifier")
	}
	event, err = n.prepareEvent(dedupeKey, severity, message)
	if err != nil {
		return err
	}
	_, err = pagerduty.ManageEvent(*event)
	if err != nil {
		return err
	}
	log.Printf("notifier: sent %q event to pagerduty for %q", event.Action, event.Payload)
	return nil
}

func (n *PDEventNotifier) prepareEvent(dedupeKey, severity, message string) (*pagerduty.V2Event, error) {
	var (
		action string
	)

	// the monitor should fail for critical severity events
	switch severity {
	default:
		return nil, fmt.Errorf("notifier: received invalid severity %q, expected 'warning' or 'info'", action)
	case "warning":
		action = "trigger"
	case "info":
		action = "resolve"
	}
	if !(len(dedupeKey) < 256) {
		return nil, fmt.Errorf("notifier: received invalid dedupeKey %s (%d long). Must be less than 256 chars", dedupeKey, len(dedupeKey))
	}

	return &pagerduty.V2Event{
		RoutingKey: n.RoutingKey,
		Action:     action, // must be trigger, acknowledge, or resolve
		DedupKey:   dedupeKey,
		Payload: &pagerduty.V2Payload{
			Summary:   message,
			Source:    n.PayloadSource,
			Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05.999Z"),
			Component: n.PayloadComponent,
			Severity:  severity, // must be critical, error, warning or info
		},
	}, nil
}
