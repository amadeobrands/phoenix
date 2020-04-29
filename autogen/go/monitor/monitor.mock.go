// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: monitor.proto

package monitor

import (
	fmt "fmt"
	math "math"
	proto "github.com/gogo/protobuf/proto"
	context "context"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

type MonitorMock struct{}

func (m *MonitorMock) Hello(ctx context.Context, req *SemverRequest) (*EmptyResponse, error) {
	res :=
		&EmptyResponse{}
	return res, nil
}
func (m *MonitorMock) Bye(ctx context.Context, req *EmptyRequest) (*EmptyResponse, error) {
	res :=
		&EmptyResponse{}
	return res, nil
}
func (m *MonitorMock) NotifyBlock(ctx context.Context, req *BlockUpdate) (*EmptyResponse, error) {
	res :=
		&EmptyResponse{}
	return res, nil
}
func (m *MonitorMock) NotifySlowdown(ctx context.Context, req *SlowdownAlert) (*EmptyResponse, error) {
	res :=
		&EmptyResponse{}
	return res, nil
}
func (m *MonitorMock) NotifyError(ctx context.Context, req *ErrorAlert) (*EmptyResponse, error) {
	res :=
		&EmptyResponse{}
	return res, nil
}
