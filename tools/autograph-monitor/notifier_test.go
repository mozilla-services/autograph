package main

import (
	_ "encoding/json"
	"reflect"
	"testing"

	"github.com/PagerDuty/go-pagerduty"
)

func TestPDEventNotifier_Send(t *testing.T) {
	type fields struct {
		RoutingKey       string
		PayloadSource    string
		PayloadComponent string
	}
	type args struct {
		dedupeKey string
		severity  string
		message   string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &PDEventNotifier{
				RoutingKey:       tt.fields.RoutingKey,
				PayloadSource:    tt.fields.PayloadSource,
				PayloadComponent: tt.fields.PayloadComponent,
			}
			if err := n.Send(tt.args.dedupeKey, tt.args.severity, tt.args.message); (err != nil) != tt.wantErr {
				t.Errorf("PDEventNotifier.Send() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPDEventNotifier_prepareEvent(t *testing.T) {
	type fields struct {
		RoutingKey       string
		PayloadSource    string
		PayloadComponent string
	}
	type args struct {
		dedupeKey string
		severity  string
		message   string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *pagerduty.V2Event
		wantErr bool
	}{
		{
			name: "warning event",
			fields: fields{
				RoutingKey:       "test-routing-key",
				PayloadSource:    "test-source",
				PayloadComponent: "test-component",
			},
			args: args{
				dedupeKey: "test.dedupkey",
				severity:  "warning",
				message:   "test message",
			},
			want: &pagerduty.V2Event{
				RoutingKey: "test-routing-key",
				Action:     "trigger",
				DedupKey:   "test.dedupkey",
				Payload: &pagerduty.V2Payload{
					Summary:   "test message",
					Source:    "test-source",
					Timestamp: "",
					Component: "test-component",
					Severity:  "warning", // must be critical, error, warning or info
				},
			},
			wantErr: false,
		},
		{
			name: "info event",
			fields: fields{
				RoutingKey:       "test-routing-key",
				PayloadSource:    "test-source",
				PayloadComponent: "test-component",
			},
			args: args{
				dedupeKey: "test.dedupkey",
				severity:  "info",
				message:   "test message",
			},
			want: &pagerduty.V2Event{
				RoutingKey: "test-routing-key",
				Action:     "resolve",
				DedupKey:   "test.dedupkey",
				Payload: &pagerduty.V2Payload{
					Summary:   "test message",
					Source:    "test-source",
					Timestamp: "",
					Component: "test-component",
					Severity:  "info", // must be critical, error, warning or info
				},
			},
			wantErr: false,
		},
		{
			name: "invalid severity event",
			fields: fields{
				RoutingKey:       "test-routing-key",
				PayloadSource:    "test-source",
				PayloadComponent: "test-component",
			},
			args: args{
				dedupeKey: "test.dedupkey",
				severity:  "critical",
				message:   "test message",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "long dedupeKey event",
			fields: fields{
				RoutingKey:       "test-routing-key",
				PayloadSource:    "test-source",
				PayloadComponent: "test-component",
			},
			args: args{
				dedupeKey: "too.long.dedupkey.dbb9239f7ad7028c3a0dea29a07a820c3250e1ed0141630e4ae77f3d3f0c2db4dbb9239f7ad7028c3a0dea29a07a820c3250e1ed0141630e4ae77f3d3f0c2db4dbb9239f7ad7028c3a0dea29a07a820c3250e1ed0141630e4ae77f3d3f0c2db4dbb9239f7ad7028c3a0dea29a07a820c3250e1ed0141630e4ae77f3d3f0c2db4dbb9239f7ad7028c3a0dea29a07a820c3250e1ed0141630e4ae77f3d3f0c2db4dbb9239f7ad7028c3a0dea29a07a820c3250e1ed0141630e4ae77f3d3f0c2db4dbb9239f7ad7028c3a0dea29a07a820c3250e1ed0141630e4ae77f3d3f0c2db4dbb9239f7ad7028c3a0dea29a07a820c3250e1ed0141630e4ae77f3d3f0c2db4dbb9239f7ad7028c3a0dea29a07a820c3250e1ed0141630e4ae77f3d3f0c2db4",
				severity:  "info",
				message:   "test message",
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &PDEventNotifier{
				RoutingKey:       tt.fields.RoutingKey,
				PayloadSource:    tt.fields.PayloadSource,
				PayloadComponent: tt.fields.PayloadComponent,
			}
			got, err := n.prepareEvent(tt.args.dedupeKey, tt.args.severity, tt.args.message)
			if (err != nil) != tt.wantErr {
				t.Errorf("PDEventNotifier.prepareEvent() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				if got != tt.want {
					t.Errorf("PDEventNotifier.prepareEvent() = %v, want %+v", got, tt.want)
				}
				return
			}
			got.Payload.Timestamp = ""
			if !reflect.DeepEqual(got.Payload, tt.want.Payload) {
				t.Errorf("PDEventNotifier.prepareEvent().Payload = %+v, want %+v", got.Payload, tt.want.Payload)
			}
			got.Payload = nil
			tt.want.Payload = nil
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PDEventNotifier.prepareEvent() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
