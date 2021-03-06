// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: wallet.proto

package node

import (
	fmt "fmt"
	proto "github.com/gogo/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type Direction int32

const (
	Direction_OUT Direction = 0
	Direction_IN  Direction = 1
)

var Direction_name = map[int32]string{
	0: "OUT",
	1: "IN",
}

var Direction_value = map[string]int32{
	"OUT": 0,
	"IN":  1,
}

func (x Direction) String() string {
	return proto.EnumName(Direction_name, int32(x))
}

func (Direction) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_b88fd140af4deb6f, []int{0}
}

type PubKey struct {
	PublicKey            []byte   `protobuf:"bytes,1,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PubKey) Reset()         { *m = PubKey{} }
func (m *PubKey) String() string { return proto.CompactTextString(m) }
func (*PubKey) ProtoMessage()    {}
func (*PubKey) Descriptor() ([]byte, []int) {
	return fileDescriptor_b88fd140af4deb6f, []int{0}
}
func (m *PubKey) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PubKey.Unmarshal(m, b)
}
func (m *PubKey) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PubKey.Marshal(b, m, deterministic)
}
func (m *PubKey) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PubKey.Merge(m, src)
}
func (m *PubKey) XXX_Size() int {
	return xxx_messageInfo_PubKey.Size(m)
}
func (m *PubKey) XXX_DiscardUnknown() {
	xxx_messageInfo_PubKey.DiscardUnknown(m)
}

var xxx_messageInfo_PubKey proto.InternalMessageInfo

func (m *PubKey) GetPublicKey() []byte {
	if m != nil {
		return m.PublicKey
	}
	return nil
}

type CreateRequest struct {
	Password             string   `protobuf:"bytes,1,opt,name=password,proto3" json:"password,omitempty"`
	Seed                 []byte   `protobuf:"bytes,2,opt,name=seed,proto3" json:"seed,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CreateRequest) Reset()         { *m = CreateRequest{} }
func (m *CreateRequest) String() string { return proto.CompactTextString(m) }
func (*CreateRequest) ProtoMessage()    {}
func (*CreateRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_b88fd140af4deb6f, []int{1}
}
func (m *CreateRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CreateRequest.Unmarshal(m, b)
}
func (m *CreateRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CreateRequest.Marshal(b, m, deterministic)
}
func (m *CreateRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CreateRequest.Merge(m, src)
}
func (m *CreateRequest) XXX_Size() int {
	return xxx_messageInfo_CreateRequest.Size(m)
}
func (m *CreateRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_CreateRequest.DiscardUnknown(m)
}

var xxx_messageInfo_CreateRequest proto.InternalMessageInfo

func (m *CreateRequest) GetPassword() string {
	if m != nil {
		return m.Password
	}
	return ""
}

func (m *CreateRequest) GetSeed() []byte {
	if m != nil {
		return m.Seed
	}
	return nil
}

type LoadRequest struct {
	Password             string   `protobuf:"bytes,1,opt,name=password,proto3" json:"password,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LoadRequest) Reset()         { *m = LoadRequest{} }
func (m *LoadRequest) String() string { return proto.CompactTextString(m) }
func (*LoadRequest) ProtoMessage()    {}
func (*LoadRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_b88fd140af4deb6f, []int{2}
}
func (m *LoadRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LoadRequest.Unmarshal(m, b)
}
func (m *LoadRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LoadRequest.Marshal(b, m, deterministic)
}
func (m *LoadRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LoadRequest.Merge(m, src)
}
func (m *LoadRequest) XXX_Size() int {
	return xxx_messageInfo_LoadRequest.Size(m)
}
func (m *LoadRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_LoadRequest.DiscardUnknown(m)
}

var xxx_messageInfo_LoadRequest proto.InternalMessageInfo

func (m *LoadRequest) GetPassword() string {
	if m != nil {
		return m.Password
	}
	return ""
}

type SessionRequest struct {
	EdPk                 []byte   `protobuf:"bytes,1,opt,name=ed_pk,json=edPk,proto3" json:"ed_pk,omitempty"`
	EdSig                []byte   `protobuf:"bytes,2,opt,name=ed_sig,json=edSig,proto3" json:"ed_sig,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SessionRequest) Reset()         { *m = SessionRequest{} }
func (m *SessionRequest) String() string { return proto.CompactTextString(m) }
func (*SessionRequest) ProtoMessage()    {}
func (*SessionRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_b88fd140af4deb6f, []int{3}
}
func (m *SessionRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SessionRequest.Unmarshal(m, b)
}
func (m *SessionRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SessionRequest.Marshal(b, m, deterministic)
}
func (m *SessionRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SessionRequest.Merge(m, src)
}
func (m *SessionRequest) XXX_Size() int {
	return xxx_messageInfo_SessionRequest.Size(m)
}
func (m *SessionRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_SessionRequest.DiscardUnknown(m)
}

var xxx_messageInfo_SessionRequest proto.InternalMessageInfo

func (m *SessionRequest) GetEdPk() []byte {
	if m != nil {
		return m.EdPk
	}
	return nil
}

func (m *SessionRequest) GetEdSig() []byte {
	if m != nil {
		return m.EdSig
	}
	return nil
}

type Session struct {
	AccessToken          string   `protobuf:"bytes,1,opt,name=access_token,json=accessToken,proto3" json:"access_token,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Session) Reset()         { *m = Session{} }
func (m *Session) String() string { return proto.CompactTextString(m) }
func (*Session) ProtoMessage()    {}
func (*Session) Descriptor() ([]byte, []int) {
	return fileDescriptor_b88fd140af4deb6f, []int{4}
}
func (m *Session) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Session.Unmarshal(m, b)
}
func (m *Session) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Session.Marshal(b, m, deterministic)
}
func (m *Session) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Session.Merge(m, src)
}
func (m *Session) XXX_Size() int {
	return xxx_messageInfo_Session.Size(m)
}
func (m *Session) XXX_DiscardUnknown() {
	xxx_messageInfo_Session.DiscardUnknown(m)
}

var xxx_messageInfo_Session proto.InternalMessageInfo

func (m *Session) GetAccessToken() string {
	if m != nil {
		return m.AccessToken
	}
	return ""
}

type LoadResponse struct {
	Key                  *PubKey  `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LoadResponse) Reset()         { *m = LoadResponse{} }
func (m *LoadResponse) String() string { return proto.CompactTextString(m) }
func (*LoadResponse) ProtoMessage()    {}
func (*LoadResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_b88fd140af4deb6f, []int{5}
}
func (m *LoadResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LoadResponse.Unmarshal(m, b)
}
func (m *LoadResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LoadResponse.Marshal(b, m, deterministic)
}
func (m *LoadResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LoadResponse.Merge(m, src)
}
func (m *LoadResponse) XXX_Size() int {
	return xxx_messageInfo_LoadResponse.Size(m)
}
func (m *LoadResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_LoadResponse.DiscardUnknown(m)
}

var xxx_messageInfo_LoadResponse proto.InternalMessageInfo

func (m *LoadResponse) GetKey() *PubKey {
	if m != nil {
		return m.Key
	}
	return nil
}

type ConsensusTxRequest struct {
	Amount               uint64   `protobuf:"fixed64,1,opt,name=amount,proto3" json:"amount,omitempty"`
	LockTime             uint64   `protobuf:"fixed64,2,opt,name=lock_time,json=lockTime,proto3" json:"lock_time,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ConsensusTxRequest) Reset()         { *m = ConsensusTxRequest{} }
func (m *ConsensusTxRequest) String() string { return proto.CompactTextString(m) }
func (*ConsensusTxRequest) ProtoMessage()    {}
func (*ConsensusTxRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_b88fd140af4deb6f, []int{6}
}
func (m *ConsensusTxRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ConsensusTxRequest.Unmarshal(m, b)
}
func (m *ConsensusTxRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ConsensusTxRequest.Marshal(b, m, deterministic)
}
func (m *ConsensusTxRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ConsensusTxRequest.Merge(m, src)
}
func (m *ConsensusTxRequest) XXX_Size() int {
	return xxx_messageInfo_ConsensusTxRequest.Size(m)
}
func (m *ConsensusTxRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_ConsensusTxRequest.DiscardUnknown(m)
}

var xxx_messageInfo_ConsensusTxRequest proto.InternalMessageInfo

func (m *ConsensusTxRequest) GetAmount() uint64 {
	if m != nil {
		return m.Amount
	}
	return 0
}

func (m *ConsensusTxRequest) GetLockTime() uint64 {
	if m != nil {
		return m.LockTime
	}
	return 0
}

type CallContractRequest struct {
	Data                 []byte   `protobuf:"bytes,1,opt,name=data,proto3" json:"data,omitempty"`
	Address              []byte   `protobuf:"bytes,2,opt,name=address,proto3" json:"address,omitempty"`
	Fee                  uint64   `protobuf:"fixed64,3,opt,name=fee,proto3" json:"fee,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CallContractRequest) Reset()         { *m = CallContractRequest{} }
func (m *CallContractRequest) String() string { return proto.CompactTextString(m) }
func (*CallContractRequest) ProtoMessage()    {}
func (*CallContractRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_b88fd140af4deb6f, []int{7}
}
func (m *CallContractRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CallContractRequest.Unmarshal(m, b)
}
func (m *CallContractRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CallContractRequest.Marshal(b, m, deterministic)
}
func (m *CallContractRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CallContractRequest.Merge(m, src)
}
func (m *CallContractRequest) XXX_Size() int {
	return xxx_messageInfo_CallContractRequest.Size(m)
}
func (m *CallContractRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_CallContractRequest.DiscardUnknown(m)
}

var xxx_messageInfo_CallContractRequest proto.InternalMessageInfo

func (m *CallContractRequest) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

func (m *CallContractRequest) GetAddress() []byte {
	if m != nil {
		return m.Address
	}
	return nil
}

func (m *CallContractRequest) GetFee() uint64 {
	if m != nil {
		return m.Fee
	}
	return 0
}

type TransferRequest struct {
	Amount               uint64   `protobuf:"fixed64,1,opt,name=amount,proto3" json:"amount,omitempty"`
	Address              []byte   `protobuf:"bytes,2,opt,name=address,proto3" json:"address,omitempty"`
	Fee                  uint64   `protobuf:"fixed64,3,opt,name=fee,proto3" json:"fee,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *TransferRequest) Reset()         { *m = TransferRequest{} }
func (m *TransferRequest) String() string { return proto.CompactTextString(m) }
func (*TransferRequest) ProtoMessage()    {}
func (*TransferRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_b88fd140af4deb6f, []int{8}
}
func (m *TransferRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_TransferRequest.Unmarshal(m, b)
}
func (m *TransferRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_TransferRequest.Marshal(b, m, deterministic)
}
func (m *TransferRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TransferRequest.Merge(m, src)
}
func (m *TransferRequest) XXX_Size() int {
	return xxx_messageInfo_TransferRequest.Size(m)
}
func (m *TransferRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_TransferRequest.DiscardUnknown(m)
}

var xxx_messageInfo_TransferRequest proto.InternalMessageInfo

func (m *TransferRequest) GetAmount() uint64 {
	if m != nil {
		return m.Amount
	}
	return 0
}

func (m *TransferRequest) GetAddress() []byte {
	if m != nil {
		return m.Address
	}
	return nil
}

func (m *TransferRequest) GetFee() uint64 {
	if m != nil {
		return m.Fee
	}
	return 0
}

type BidRequest struct {
	Amount               uint64   `protobuf:"fixed64,1,opt,name=amount,proto3" json:"amount,omitempty"`
	Fee                  uint64   `protobuf:"fixed64,2,opt,name=fee,proto3" json:"fee,omitempty"`
	Locktime             uint64   `protobuf:"fixed64,3,opt,name=locktime,proto3" json:"locktime,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *BidRequest) Reset()         { *m = BidRequest{} }
func (m *BidRequest) String() string { return proto.CompactTextString(m) }
func (*BidRequest) ProtoMessage()    {}
func (*BidRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_b88fd140af4deb6f, []int{9}
}
func (m *BidRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_BidRequest.Unmarshal(m, b)
}
func (m *BidRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_BidRequest.Marshal(b, m, deterministic)
}
func (m *BidRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_BidRequest.Merge(m, src)
}
func (m *BidRequest) XXX_Size() int {
	return xxx_messageInfo_BidRequest.Size(m)
}
func (m *BidRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_BidRequest.DiscardUnknown(m)
}

var xxx_messageInfo_BidRequest proto.InternalMessageInfo

func (m *BidRequest) GetAmount() uint64 {
	if m != nil {
		return m.Amount
	}
	return 0
}

func (m *BidRequest) GetFee() uint64 {
	if m != nil {
		return m.Fee
	}
	return 0
}

func (m *BidRequest) GetLocktime() uint64 {
	if m != nil {
		return m.Locktime
	}
	return 0
}

type StakeRequest struct {
	Amount               uint64   `protobuf:"fixed64,1,opt,name=amount,proto3" json:"amount,omitempty"`
	Fee                  uint64   `protobuf:"fixed64,2,opt,name=fee,proto3" json:"fee,omitempty"`
	Locktime             uint64   `protobuf:"fixed64,3,opt,name=locktime,proto3" json:"locktime,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *StakeRequest) Reset()         { *m = StakeRequest{} }
func (m *StakeRequest) String() string { return proto.CompactTextString(m) }
func (*StakeRequest) ProtoMessage()    {}
func (*StakeRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_b88fd140af4deb6f, []int{10}
}
func (m *StakeRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_StakeRequest.Unmarshal(m, b)
}
func (m *StakeRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_StakeRequest.Marshal(b, m, deterministic)
}
func (m *StakeRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_StakeRequest.Merge(m, src)
}
func (m *StakeRequest) XXX_Size() int {
	return xxx_messageInfo_StakeRequest.Size(m)
}
func (m *StakeRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_StakeRequest.DiscardUnknown(m)
}

var xxx_messageInfo_StakeRequest proto.InternalMessageInfo

func (m *StakeRequest) GetAmount() uint64 {
	if m != nil {
		return m.Amount
	}
	return 0
}

func (m *StakeRequest) GetFee() uint64 {
	if m != nil {
		return m.Fee
	}
	return 0
}

func (m *StakeRequest) GetLocktime() uint64 {
	if m != nil {
		return m.Locktime
	}
	return 0
}

type TransactionResponse struct {
	Hash                 []byte   `protobuf:"bytes,1,opt,name=hash,proto3" json:"hash,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *TransactionResponse) Reset()         { *m = TransactionResponse{} }
func (m *TransactionResponse) String() string { return proto.CompactTextString(m) }
func (*TransactionResponse) ProtoMessage()    {}
func (*TransactionResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_b88fd140af4deb6f, []int{11}
}
func (m *TransactionResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_TransactionResponse.Unmarshal(m, b)
}
func (m *TransactionResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_TransactionResponse.Marshal(b, m, deterministic)
}
func (m *TransactionResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TransactionResponse.Merge(m, src)
}
func (m *TransactionResponse) XXX_Size() int {
	return xxx_messageInfo_TransactionResponse.Size(m)
}
func (m *TransactionResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_TransactionResponse.DiscardUnknown(m)
}

var xxx_messageInfo_TransactionResponse proto.InternalMessageInfo

func (m *TransactionResponse) GetHash() []byte {
	if m != nil {
		return m.Hash
	}
	return nil
}

type WalletStatusResponse struct {
	Loaded               bool     `protobuf:"varint,1,opt,name=loaded,proto3" json:"loaded,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *WalletStatusResponse) Reset()         { *m = WalletStatusResponse{} }
func (m *WalletStatusResponse) String() string { return proto.CompactTextString(m) }
func (*WalletStatusResponse) ProtoMessage()    {}
func (*WalletStatusResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_b88fd140af4deb6f, []int{12}
}
func (m *WalletStatusResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_WalletStatusResponse.Unmarshal(m, b)
}
func (m *WalletStatusResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_WalletStatusResponse.Marshal(b, m, deterministic)
}
func (m *WalletStatusResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_WalletStatusResponse.Merge(m, src)
}
func (m *WalletStatusResponse) XXX_Size() int {
	return xxx_messageInfo_WalletStatusResponse.Size(m)
}
func (m *WalletStatusResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_WalletStatusResponse.DiscardUnknown(m)
}

var xxx_messageInfo_WalletStatusResponse proto.InternalMessageInfo

func (m *WalletStatusResponse) GetLoaded() bool {
	if m != nil {
		return m.Loaded
	}
	return false
}

type SyncProgressResponse struct {
	Progress             float32  `protobuf:"fixed32,1,opt,name=progress,proto3" json:"progress,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SyncProgressResponse) Reset()         { *m = SyncProgressResponse{} }
func (m *SyncProgressResponse) String() string { return proto.CompactTextString(m) }
func (*SyncProgressResponse) ProtoMessage()    {}
func (*SyncProgressResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_b88fd140af4deb6f, []int{13}
}
func (m *SyncProgressResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SyncProgressResponse.Unmarshal(m, b)
}
func (m *SyncProgressResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SyncProgressResponse.Marshal(b, m, deterministic)
}
func (m *SyncProgressResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SyncProgressResponse.Merge(m, src)
}
func (m *SyncProgressResponse) XXX_Size() int {
	return xxx_messageInfo_SyncProgressResponse.Size(m)
}
func (m *SyncProgressResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_SyncProgressResponse.DiscardUnknown(m)
}

var xxx_messageInfo_SyncProgressResponse proto.InternalMessageInfo

func (m *SyncProgressResponse) GetProgress() float32 {
	if m != nil {
		return m.Progress
	}
	return 0
}

type BalanceResponse struct {
	UnlockedBalance      uint64   `protobuf:"fixed64,1,opt,name=unlockedBalance,proto3" json:"unlockedBalance,omitempty"`
	LockedBalance        uint64   `protobuf:"fixed64,2,opt,name=lockedBalance,proto3" json:"lockedBalance,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *BalanceResponse) Reset()         { *m = BalanceResponse{} }
func (m *BalanceResponse) String() string { return proto.CompactTextString(m) }
func (*BalanceResponse) ProtoMessage()    {}
func (*BalanceResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_b88fd140af4deb6f, []int{14}
}
func (m *BalanceResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_BalanceResponse.Unmarshal(m, b)
}
func (m *BalanceResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_BalanceResponse.Marshal(b, m, deterministic)
}
func (m *BalanceResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_BalanceResponse.Merge(m, src)
}
func (m *BalanceResponse) XXX_Size() int {
	return xxx_messageInfo_BalanceResponse.Size(m)
}
func (m *BalanceResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_BalanceResponse.DiscardUnknown(m)
}

var xxx_messageInfo_BalanceResponse proto.InternalMessageInfo

func (m *BalanceResponse) GetUnlockedBalance() uint64 {
	if m != nil {
		return m.UnlockedBalance
	}
	return 0
}

func (m *BalanceResponse) GetLockedBalance() uint64 {
	if m != nil {
		return m.LockedBalance
	}
	return 0
}

type TxRecord struct {
	Height               uint64    `protobuf:"fixed64,1,opt,name=height,proto3" json:"height,omitempty"`
	Direction            Direction `protobuf:"varint,2,opt,name=direction,proto3,enum=node.Direction" json:"direction,omitempty"`
	Timestamp            int64     `protobuf:"varint,3,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	Type                 TxType    `protobuf:"varint,4,opt,name=type,proto3,enum=node.TxType" json:"type,omitempty"`
	Amount               uint64    `protobuf:"fixed64,5,opt,name=amount,proto3" json:"amount,omitempty"`
	Fee                  uint64    `protobuf:"fixed64,6,opt,name=fee,proto3" json:"fee,omitempty"`
	UnlockHeight         uint64    `protobuf:"fixed64,7,opt,name=unlockHeight,proto3" json:"unlockHeight,omitempty"`
	Hash                 []byte    `protobuf:"bytes,8,opt,name=hash,proto3" json:"hash,omitempty"`
	Data                 []byte    `protobuf:"bytes,9,opt,name=data,proto3" json:"data,omitempty"`
	Obfuscated           bool      `protobuf:"varint,10,opt,name=obfuscated,proto3" json:"obfuscated,omitempty"`
	XXX_NoUnkeyedLiteral struct{}  `json:"-"`
	XXX_unrecognized     []byte    `json:"-"`
	XXX_sizecache        int32     `json:"-"`
}

func (m *TxRecord) Reset()         { *m = TxRecord{} }
func (m *TxRecord) String() string { return proto.CompactTextString(m) }
func (*TxRecord) ProtoMessage()    {}
func (*TxRecord) Descriptor() ([]byte, []int) {
	return fileDescriptor_b88fd140af4deb6f, []int{15}
}
func (m *TxRecord) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_TxRecord.Unmarshal(m, b)
}
func (m *TxRecord) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_TxRecord.Marshal(b, m, deterministic)
}
func (m *TxRecord) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TxRecord.Merge(m, src)
}
func (m *TxRecord) XXX_Size() int {
	return xxx_messageInfo_TxRecord.Size(m)
}
func (m *TxRecord) XXX_DiscardUnknown() {
	xxx_messageInfo_TxRecord.DiscardUnknown(m)
}

var xxx_messageInfo_TxRecord proto.InternalMessageInfo

func (m *TxRecord) GetHeight() uint64 {
	if m != nil {
		return m.Height
	}
	return 0
}

func (m *TxRecord) GetDirection() Direction {
	if m != nil {
		return m.Direction
	}
	return Direction_OUT
}

func (m *TxRecord) GetTimestamp() int64 {
	if m != nil {
		return m.Timestamp
	}
	return 0
}

func (m *TxRecord) GetType() TxType {
	if m != nil {
		return m.Type
	}
	return TxType_STANDARD
}

func (m *TxRecord) GetAmount() uint64 {
	if m != nil {
		return m.Amount
	}
	return 0
}

func (m *TxRecord) GetFee() uint64 {
	if m != nil {
		return m.Fee
	}
	return 0
}

func (m *TxRecord) GetUnlockHeight() uint64 {
	if m != nil {
		return m.UnlockHeight
	}
	return 0
}

func (m *TxRecord) GetHash() []byte {
	if m != nil {
		return m.Hash
	}
	return nil
}

func (m *TxRecord) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

func (m *TxRecord) GetObfuscated() bool {
	if m != nil {
		return m.Obfuscated
	}
	return false
}

type TxHistoryResponse struct {
	Records              []*TxRecord `protobuf:"bytes,1,rep,name=records,proto3" json:"records,omitempty"`
	XXX_NoUnkeyedLiteral struct{}    `json:"-"`
	XXX_unrecognized     []byte      `json:"-"`
	XXX_sizecache        int32       `json:"-"`
}

func (m *TxHistoryResponse) Reset()         { *m = TxHistoryResponse{} }
func (m *TxHistoryResponse) String() string { return proto.CompactTextString(m) }
func (*TxHistoryResponse) ProtoMessage()    {}
func (*TxHistoryResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_b88fd140af4deb6f, []int{16}
}
func (m *TxHistoryResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_TxHistoryResponse.Unmarshal(m, b)
}
func (m *TxHistoryResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_TxHistoryResponse.Marshal(b, m, deterministic)
}
func (m *TxHistoryResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TxHistoryResponse.Merge(m, src)
}
func (m *TxHistoryResponse) XXX_Size() int {
	return xxx_messageInfo_TxHistoryResponse.Size(m)
}
func (m *TxHistoryResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_TxHistoryResponse.DiscardUnknown(m)
}

var xxx_messageInfo_TxHistoryResponse proto.InternalMessageInfo

func (m *TxHistoryResponse) GetRecords() []*TxRecord {
	if m != nil {
		return m.Records
	}
	return nil
}

func init() {
	proto.RegisterEnum("node.Direction", Direction_name, Direction_value)
	proto.RegisterType((*PubKey)(nil), "node.PubKey")
	proto.RegisterType((*CreateRequest)(nil), "node.CreateRequest")
	proto.RegisterType((*LoadRequest)(nil), "node.LoadRequest")
	proto.RegisterType((*SessionRequest)(nil), "node.SessionRequest")
	proto.RegisterType((*Session)(nil), "node.Session")
	proto.RegisterType((*LoadResponse)(nil), "node.LoadResponse")
	proto.RegisterType((*ConsensusTxRequest)(nil), "node.ConsensusTxRequest")
	proto.RegisterType((*CallContractRequest)(nil), "node.CallContractRequest")
	proto.RegisterType((*TransferRequest)(nil), "node.TransferRequest")
	proto.RegisterType((*BidRequest)(nil), "node.BidRequest")
	proto.RegisterType((*StakeRequest)(nil), "node.StakeRequest")
	proto.RegisterType((*TransactionResponse)(nil), "node.TransactionResponse")
	proto.RegisterType((*WalletStatusResponse)(nil), "node.WalletStatusResponse")
	proto.RegisterType((*SyncProgressResponse)(nil), "node.SyncProgressResponse")
	proto.RegisterType((*BalanceResponse)(nil), "node.BalanceResponse")
	proto.RegisterType((*TxRecord)(nil), "node.TxRecord")
	proto.RegisterType((*TxHistoryResponse)(nil), "node.TxHistoryResponse")
}

func init() { proto.RegisterFile("wallet.proto", fileDescriptor_b88fd140af4deb6f) }

var fileDescriptor_b88fd140af4deb6f = []byte{
	// 690 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xac, 0x54, 0x5b, 0x6b, 0xdb, 0x4c,
	0x10, 0xfd, 0x62, 0x3b, 0xb2, 0x3d, 0x76, 0xe2, 0x7c, 0x9b, 0x34, 0x98, 0x34, 0x0d, 0xe9, 0x52,
	0xa8, 0x13, 0x1a, 0x1b, 0xdc, 0xd7, 0x96, 0x42, 0xdc, 0x87, 0x84, 0x94, 0x36, 0xc8, 0x0a, 0x85,
	0xbe, 0x98, 0xb5, 0x76, 0x6c, 0x0b, 0x5d, 0x56, 0xd5, 0xae, 0x48, 0xf4, 0x8b, 0xfa, 0x37, 0xcb,
	0xae, 0x2e, 0x76, 0x4a, 0x21, 0x2d, 0xf4, 0x6d, 0xe7, 0xcc, 0x45, 0x33, 0xe7, 0xcc, 0x08, 0xba,
	0xf7, 0x2c, 0x08, 0x50, 0x0d, 0xe3, 0x44, 0x28, 0x41, 0x1a, 0x91, 0xe0, 0x78, 0xb4, 0x13, 0x62,
	0x18, 0x0b, 0x11, 0xe4, 0x20, 0x7d, 0x0d, 0xd6, 0x6d, 0x3a, 0xbf, 0xc1, 0x8c, 0xbc, 0x00, 0x88,
	0xd3, 0x79, 0xe0, 0xb9, 0x33, 0x1f, 0xb3, 0xfe, 0xd6, 0xe9, 0xd6, 0xa0, 0x6b, 0xb7, 0x73, 0xe4,
	0x06, 0x33, 0xfa, 0x01, 0x76, 0x26, 0x09, 0x32, 0x85, 0x36, 0x7e, 0x4f, 0x51, 0x2a, 0x72, 0x04,
	0xad, 0x98, 0x49, 0x79, 0x2f, 0x12, 0x6e, 0xa2, 0xdb, 0x76, 0x65, 0x13, 0x02, 0x0d, 0x89, 0xc8,
	0xfb, 0x35, 0x53, 0xc5, 0xbc, 0xe9, 0x19, 0x74, 0x3e, 0x09, 0xc6, 0xff, 0x20, 0x9d, 0xbe, 0x83,
	0xdd, 0x29, 0x4a, 0xe9, 0x89, 0xa8, 0x8c, 0xde, 0x87, 0x6d, 0xe4, 0xb3, 0xd8, 0x2f, 0xfa, 0x6a,
	0x20, 0xbf, 0xf5, 0xc9, 0x33, 0xb0, 0x90, 0xcf, 0xa4, 0xb7, 0x2c, 0xbe, 0xb3, 0x8d, 0x7c, 0xea,
	0x2d, 0xe9, 0x1b, 0x68, 0x16, 0xd9, 0xe4, 0x25, 0x74, 0x99, 0xeb, 0xa2, 0x94, 0x33, 0x25, 0x7c,
	0x8c, 0x8a, 0x0f, 0x75, 0x72, 0xcc, 0xd1, 0x10, 0x1d, 0x42, 0x37, 0x6f, 0x4b, 0xc6, 0x22, 0x92,
	0x48, 0x4e, 0xa0, 0x5e, 0xce, 0xdf, 0x19, 0x77, 0x87, 0x9a, 0xb3, 0x61, 0xce, 0x90, 0xad, 0x1d,
	0xf4, 0x1a, 0xc8, 0x44, 0x07, 0x46, 0x32, 0x95, 0xce, 0x43, 0xd9, 0xdf, 0x21, 0x58, 0x2c, 0x14,
	0x69, 0xa4, 0x4c, 0xa2, 0x65, 0x17, 0x16, 0x79, 0x0e, 0xed, 0x40, 0xb8, 0xfe, 0x4c, 0x79, 0x21,
	0x9a, 0x2e, 0x2d, 0xbb, 0xa5, 0x01, 0xc7, 0x0b, 0x91, 0xde, 0xc1, 0xfe, 0x84, 0x05, 0xc1, 0x44,
	0x44, 0x2a, 0x61, 0xae, 0x2a, 0x6b, 0x11, 0x68, 0x70, 0xa6, 0x58, 0x39, 0xaa, 0x7e, 0x93, 0x3e,
	0x34, 0x19, 0xe7, 0x09, 0x4a, 0x59, 0xcc, 0x5a, 0x9a, 0x64, 0x0f, 0xea, 0x0b, 0xc4, 0x7e, 0xdd,
	0xd4, 0xd6, 0x4f, 0x7a, 0x07, 0x3d, 0x27, 0x61, 0x91, 0x5c, 0x60, 0xf2, 0x54, 0x7b, 0x7f, 0x53,
	0xd6, 0x06, 0xb8, 0xf4, 0xf8, 0x53, 0x15, 0x8b, 0xbc, 0x5a, 0x95, 0xa7, 0x85, 0xd6, 0x13, 0x1b,
	0x06, 0xea, 0x6b, 0x06, 0xb4, 0x4d, 0x1d, 0xe8, 0x4e, 0x15, 0xf3, 0xf1, 0xdf, 0x56, 0x3d, 0x83,
	0x7d, 0x43, 0x00, 0x73, 0x95, 0x59, 0xa1, 0x42, 0x59, 0x02, 0x8d, 0x15, 0x93, 0xab, 0x92, 0x57,
	0xfd, 0xa6, 0x43, 0x38, 0xf8, 0x6a, 0x6e, 0x64, 0xaa, 0x98, 0x4a, 0x65, 0x15, 0x7b, 0x08, 0x56,
	0x20, 0x18, 0xc7, 0x7c, 0x37, 0x5b, 0x76, 0x61, 0xd1, 0x31, 0x1c, 0x4c, 0xb3, 0xc8, 0xbd, 0x4d,
	0xc4, 0x52, 0xd3, 0x54, 0xc5, 0xeb, 0x6d, 0x2e, 0x30, 0x93, 0x51, 0xb3, 0x2b, 0x9b, 0x32, 0xe8,
	0x5d, 0xb2, 0x80, 0x45, 0x2e, 0x56, 0xe1, 0x03, 0xe8, 0xa5, 0x91, 0xee, 0x17, 0x79, 0xe1, 0x2a,
	0x06, 0xfe, 0x15, 0x26, 0xaf, 0x60, 0xe7, 0x71, 0x5c, 0xce, 0xc1, 0x63, 0x90, 0xfe, 0xa8, 0x41,
	0x4b, 0x2f, 0xa3, 0xab, 0x8f, 0xef, 0x10, 0xac, 0x15, 0x7a, 0xcb, 0x55, 0x45, 0x62, 0x6e, 0x91,
	0x0b, 0x68, 0x73, 0x2f, 0x41, 0x43, 0x8a, 0x29, 0xb3, 0x3b, 0xee, 0xe5, 0xfb, 0xfd, 0xb1, 0x84,
	0xed, 0x75, 0x04, 0x39, 0x86, 0xb6, 0x66, 0x53, 0x2a, 0x16, 0xc6, 0x86, 0xe2, 0xba, 0xbd, 0x06,
	0xc8, 0x29, 0x34, 0x54, 0x16, 0x63, 0xbf, 0x61, 0xea, 0x14, 0x77, 0xe2, 0x3c, 0x38, 0x59, 0x8c,
	0xb6, 0xf1, 0x6c, 0x68, 0xb9, 0xfd, 0x3b, 0x2d, 0xad, 0xb5, 0x96, 0x14, 0xba, 0xf9, 0xd8, 0x57,
	0x79, 0xdb, 0x4d, 0xe3, 0x7a, 0x84, 0x55, 0xe2, 0xb5, 0xd6, 0xe2, 0x55, 0x87, 0xd2, 0xde, 0x38,
	0x94, 0x13, 0x00, 0x31, 0x5f, 0xa4, 0xd2, 0x65, 0x0a, 0x79, 0x1f, 0x8c, 0x78, 0x1b, 0x08, 0x7d,
	0x0f, 0xff, 0x3b, 0x0f, 0x57, 0x9e, 0x54, 0x22, 0xc9, 0x36, 0xe4, 0x68, 0x26, 0x86, 0x3b, 0x2d,
	0x5e, 0x7d, 0xd0, 0x19, 0xef, 0x96, 0xf3, 0xe4, 0x94, 0xda, 0xa5, 0xfb, 0xfc, 0x18, 0xda, 0x15,
	0x59, 0xa4, 0x09, 0xf5, 0x2f, 0x77, 0xce, 0xde, 0x7f, 0xc4, 0x82, 0xda, 0xf5, 0xe7, 0xbd, 0xad,
	0xcb, 0xf3, 0x6f, 0x83, 0xa5, 0xa7, 0x56, 0xe9, 0x7c, 0xe8, 0x8a, 0x70, 0xc4, 0x53, 0xe9, 0x5f,
	0x98, 0xbf, 0xec, 0x3c, 0x5d, 0x8c, 0x58, 0xaa, 0xc4, 0x12, 0xa3, 0xd1, 0x52, 0x8c, 0x74, 0xed,
	0xb9, 0x65, 0x3c, 0x6f, 0x7f, 0x06, 0x00, 0x00, 0xff, 0xff, 0xb0, 0x56, 0xd3, 0x2a, 0xa4, 0x05,
	0x00, 0x00,
}
