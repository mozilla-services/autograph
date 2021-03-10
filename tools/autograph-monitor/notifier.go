package main

import (
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sns"
)

// Notifier is an interface for sending warnings
type Notifier interface {
	// Send writes a message with an id to a notification channel
	Send(id, message string) error
}

// SNSNotifier sends warnings to an AWS SNS Topic
type SNSNotifier struct {
	Topic string
}

// Send publishes a message to the give AWS SNS Topic
func (n *SNSNotifier) Send(id, message string) error {
	if n == nil || n.Topic == "" {
		// We're not running in lambda or the conf isnt ready so don't try to publish to SQS
		log.Printf("soft notification ID %s: %s", id, message)
		return nil
	}
	svc := sns.New(session.New())
	params := &sns.PublishInput{
		Message:  aws.String(message),
		TopicArn: aws.String(n.Topic),
	}
	_, err := svc.Publish(params)
	if err != nil {
		return err
	}
	log.Printf("Soft notification send to %q with body: %s", n.Topic, *params.Message)
	return nil
}
