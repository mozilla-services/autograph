module github.com/mozilla-services/autograph/tools/autograph-monitor

go 1.13

require (
	github.com/PagerDuty/go-pagerduty v1.3.0
	github.com/aws/aws-lambda-go v1.22.0
	github.com/aws/aws-sdk-go v1.37.30
	github.com/golang/mock v1.5.0
	github.com/mozilla-services/autograph v0.0.0-20200224202955-7cd80491527d
	go.mozilla.org/hawk v0.0.0-20190327210923-a483e4a7047e
	go.mozilla.org/mar v0.0.0-20200124173325-c51ce05c9f3d
)

replace github.com/mozilla-services/autograph => ../../.
