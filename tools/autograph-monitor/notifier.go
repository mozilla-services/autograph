package main

// Notifier is an interface for sending and resolving warning notifications
type Notifier interface {
	// Send writes a message with an id to a notification channel
	Send(id, severity, message string) error
}
