module go.mozilla.org/autograph/tools/autograph-monitor

go 1.13

require (
	github.com/aws/aws-lambda-go v1.20.0
	github.com/aws/aws-sdk-go v1.35.19
	go.mozilla.org/autograph v0.0.0-20200224202955-7cd80491527d
	go.mozilla.org/hawk v0.0.0-20190327210923-a483e4a7047e
	go.mozilla.org/mar v0.0.0-20200124173325-c51ce05c9f3d
)

replace go.mozilla.org/autograph => ../../.
