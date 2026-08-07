// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fault

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"cloud.google.com/kms/integrations/fakekms/fault/faultpb"
	"cloud.google.com/kms/integrations/fakekms/fault/mathpb"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

var _ mathpb.MathServiceServer = (*mathServer)(nil)

type mathServer struct{}

func (s *mathServer) Add(ctx context.Context, req *mathpb.AddRequest) (*mathpb.AddResponse, error) {
	return &mathpb.AddResponse{Sum: req.X + req.Y}, nil
}

func (s *mathServer) Multiply(ctx context.Context, req *mathpb.MultiplyRequest) (*mathpb.MultiplyResponse, error) {
	return &mathpb.MultiplyResponse{Product: req.X * req.Y}, nil
}

func startTestServer(ctx context.Context) (*grpc.ClientConn, func(), error) {
	lis := bufconn.Listen(1024)

	fs := new(Server)
	ms := new(mathServer)
	srv := grpc.NewServer(grpc.ChainUnaryInterceptor(fs.NewInterceptor()))
	faultpb.RegisterFaultServiceServer(srv, fs)
	mathpb.RegisterMathServiceServer(srv, ms)

	go srv.Serve(lis)

	conn, err := grpc.DialContext(ctx, "", grpc.WithInsecure(),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
	)
	if err != nil {
		return nil, nil, err
	}

	return conn, func() {
		conn.Close()
		srv.Stop()
		lis.Close()
	}, nil
}

func TestAddWithoutFaultReturnsSum(t *testing.T) {
	ctx := context.Background()
	conn, cancel, err := startTestServer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	mathClient := mathpb.NewMathServiceClient(conn)
	resp, err := mathClient.Add(ctx, &mathpb.AddRequest{X: 2, Y: 2})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Sum != 4 {
		t.Errorf("Add(X: 2, Y: 2)=%d, want 4", resp.Sum)
	}
}

func TestFaultWithoutMethodReturnsFault(t *testing.T) {
	ctx := context.Background()
	conn, cancel, err := startTestServer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	faultClient := faultpb.NewFaultServiceClient(conn)
	_, err = faultClient.AddFault(ctx, &faultpb.Fault{
		ResponseAction: &faultpb.ResponseAction{
			Error: &statuspb.Status{Code: int32(codes.DeadlineExceeded)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	mathClient := mathpb.NewMathServiceClient(conn)
	resp, err := mathClient.Add(ctx, &mathpb.AddRequest{})
	if resp != nil {
		t.Errorf("resp=%+v, want nil", resp)
	}
	if status.Code(err) != codes.DeadlineExceeded {
		t.Errorf("status.Code(err)=%v, want DeadlineExceeded", status.Code(err))
	}
}

func TestFaultIsEmittedWhenMethodNameMatches(t *testing.T) {
	ctx := context.Background()
	conn, cancel, err := startTestServer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	faultClient := faultpb.NewFaultServiceClient(conn)
	_, err = faultClient.AddFault(ctx, &faultpb.Fault{
		RequestMatcher: &faultpb.RequestMatcher{MethodName: "Add"},
		ResponseAction: &faultpb.ResponseAction{
			Error: &statuspb.Status{Code: int32(codes.Unknown)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	mathClient := mathpb.NewMathServiceClient(conn)
	resp, err := mathClient.Add(ctx, &mathpb.AddRequest{})
	if resp != nil {
		t.Errorf("resp=%+v, want nil", resp)
	}
	if status.Code(err) != codes.Unknown {
		t.Errorf("status.Code(err)=%v, want Unknown", status.Code(err))
	}
}

func TestFaultIsNotEmittedWhenMethodDoesNotMatch(t *testing.T) {
	ctx := context.Background()
	conn, cancel, err := startTestServer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	faultClient := faultpb.NewFaultServiceClient(conn)
	_, err = faultClient.AddFault(ctx, &faultpb.Fault{
		RequestMatcher: &faultpb.RequestMatcher{MethodName: "Add"},
		ResponseAction: &faultpb.ResponseAction{
			Error: &statuspb.Status{Code: int32(codes.FailedPrecondition)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	mathClient := mathpb.NewMathServiceClient(conn)
	resp, err := mathClient.Multiply(ctx, &mathpb.MultiplyRequest{X: 2, Y: 3})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Product != 6 {
		t.Errorf("Multiply(X: 2, Y: 3)=%d, want 6", resp.Product)
	}
}

func TestFaultIsEmittedOnlyOnce(t *testing.T) {
	ctx := context.Background()
	conn, cancel, err := startTestServer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	faultClient := faultpb.NewFaultServiceClient(conn)
	_, err = faultClient.AddFault(ctx, &faultpb.Fault{
		ResponseAction: &faultpb.ResponseAction{
			Error: &statuspb.Status{Code: int32(codes.FailedPrecondition)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	mathClient := mathpb.NewMathServiceClient(conn)
	resp, err := mathClient.Multiply(ctx, &mathpb.MultiplyRequest{})
	if resp != nil {
		t.Errorf("resp=%+v, want nil", resp)
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("status.Code(err)=%v, want FailedPrecondition", status.Code(err))
	}

	resp, err = mathClient.Multiply(ctx, &mathpb.MultiplyRequest{X: 2, Y: 3})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Product != 6 {
		t.Errorf("Multiply(X: 2, Y: 3)=%d, want 6", resp.Product)
	}
}

func TestFirstRequestNormalSecondRequestFault(t *testing.T) {
	ctx := context.Background()
	conn, cancel, err := startTestServer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	faultClient := faultpb.NewFaultServiceClient(conn)
	// Empty fault should trigger normal behavior for first request.
	if _, err := faultClient.AddFault(ctx, &faultpb.Fault{}); err != nil {
		t.Fatal(err)
	}
	// Added fault should trigger fault for second request.
	_, err = faultClient.AddFault(ctx, &faultpb.Fault{
		ResponseAction: &faultpb.ResponseAction{
			Error: &statuspb.Status{Code: int32(codes.PermissionDenied)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	mathClient := mathpb.NewMathServiceClient(conn)
	resp, err := mathClient.Multiply(ctx, &mathpb.MultiplyRequest{X: 2, Y: 3})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Product != 6 {
		t.Errorf("Multiply(X: 2, Y: 3)=%d, want 6", resp.Product)
	}

	resp, err = mathClient.Multiply(ctx, &mathpb.MultiplyRequest{})
	if resp != nil {
		t.Errorf("resp=%+v, want nil", resp)
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("status.Code(err)=%v, want PermissionDenied", status.Code(err))
	}
}

func TestDelay(t *testing.T) {
	ctx := context.Background()
	conn, cancel, err := startTestServer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	delay := 500 * time.Millisecond
	faultClient := faultpb.NewFaultServiceClient(conn)
	_, err = faultClient.AddFault(ctx, &faultpb.Fault{
		ResponseAction: &faultpb.ResponseAction{
			Delay: durationpb.New(delay),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	mathClient := mathpb.NewMathServiceClient(conn)
	begin := time.Now()
	resp, err := mathClient.Multiply(ctx, &mathpb.MultiplyRequest{X: 2, Y: 3})
	duration := time.Now().Sub(begin)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Product != 6 {
		t.Errorf("Multiply(X: 2, Y: 3)=%d, want 6", resp.Product)
	}

	if duration < delay {
		t.Errorf("duration=%v, want >= %v", duration, delay)
	}
}
