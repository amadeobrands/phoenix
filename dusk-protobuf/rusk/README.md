# Protocol Documentation

## Table of Contents

- [consensus.proto](#consensus.proto)
	- [DistributeRequest](#rusk.DistributeRequest)
	- [WithdrawRequest](#rusk.WithdrawRequest)
	- [StakeRequest](#rusk.StakeRequest)
	- [WithdrawStakeRequest](#rusk.WithdrawStakeRequest)
	- [SlashRequest](#rusk.SlashRequest)
	- [BidRequest](#rusk.BidRequest)
	- [WithdrawBidRequest](#rusk.WithdrawBidRequest)

- [field.proto](#field.proto)
    - [CompressedPoint](#rusk.CompressedPoint)
    - [Nonce](#rusk.Nonce)
    - [Scalar](#rusk.Scalar)

- [keys.proto](#keys.proto)
    - [PublicKey](#rusk.PublicKey)
    - [SecretKey](#rusk.SecretKey)
    - [ViewKey](#rusk.ViewKey)

- [note.proto](#note.proto)
    - [DecryptedNote](#rusk.DecryptedNote)
    - [Note](#rusk.Note)
    - [Nullifier](#rusk.Nullifier)
    - [NoteType](#rusk.NoteType)

- [rusk.proto](#rusk.proto)
    - [Rusk](#rusk.Rusk)
    - [EchoRequest](#rusk.EchoRequest)
    - [EchoResponse](#rusk.EchoResponse)
	- [ContractCall](#rusk.ContractCall)
    - [ValidateStateTransitionRequest](#rusk.ValidateStateTransitionRequest)
    - [ValidateStateTransitionResponse](#rusk.ValidateStateTransitionResponse)
    - [ExecuteStateTransitionRequest](#rusk.ExecuteStateTransitionRequest)
    - [ExecuteStateTransitionResponse](#rusk.ExecuteStateTransitionResponse)
    - [GenerateSecretKeyRequest](#rusk.GenerateSecretKeyRequest)
    - [KeysResponse](#rusk.KeysResponse)
    - [NewTransactionRequest](#rusk.NewTransactionRequest)
    - [VerifyTransactionResponse](#rusk.VerifyTransactionResponse)
    - [SlashTransactionRequest](#rusk.SlashTransactionRequest)
    - [SlashTransactionResponse](#rusk.SlashTransactionResponse)
    - [WithdrawFeesTransactionRequest](#rusk.WithdrawFeesRequest)
    - [WithdrawFeesTransactionResponse](#rusk.WithdrawFeesResponse)
    - [DistributeTransactionRequest](#rusk.DistributeTransactionRequest)
    - [DistributeTransactionResponse](#rusk.DistributeTransactionResponse)
    - [BidTransactionRequest](#rusk.BidTransactionRequest)
    - [BidTransactionResponse](#rusk.BidTransactionResponse)
    - [StakeTransactionRequest](#rusk.StakeTransactionRequest)
    - [StakeTransactionResponse](#rusk.StakeTransactionResponse)
    - [WithdrawBidTransactionRequest](#rusk.WithdrawBidTransactionRequest)
    - [WithdrawBidTransactionResponse](#rusk.WithdrawBidTransactionResponse)
    - [WithdrawStakeTransactionRequest](#rusk.WithdrawStakeTransactionRequest)
    - [WithdrawStakeTransactionResponse](#rusk.WithdrawStakeTransactionResponse)

    - [Crypto](#rusk.Crypto)
    - [HashRequest](#rusk.HashRequest)
    - [HashResponse](#rusk.HashResponse)

- [transaction.proto](#transaction.proto)
    - [Transaction](#rusk.Transaction)
    - [TransactionInput](#rusk.TransactionInput)
    - [TransactionOutput](#rusk.TransactionOutput)

- [Scalar Value Types](#scalar-value-types)

## consensus.proto

### DistributeTransaction

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| total_reward | [fixed64](#fixed64) |  | Total block reward (coinbase + fees) |
| provisioners_addresses | [bytes](#bytes) |  | The addresses of all provisioners involved in finalizing the block |
| bg_pk | [PublicKey](#rusk.PublicKey) |  | Wallet public key of the block generator who made the block |
| tx | [Transaction](#rusk.Transaction) |  | Transaction underlying the contract call |

### WithdrawTransaction

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bls_key | [bytes](#bytes) |  | BLS public key of the node requesting withdrawal |
| sig | [bytes](#bytes) |  | A signature made using the BLS key, to prove ownership of said key |
| msg | [bytes](#bytes) |  | The message signed with the BLS key |
| tx | [Transaction](#rusk.Transaction) |  | Transaction underlying the contract call |

### StakeTransaction

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bls_key | [bytes](#bytes) |  | The BLS public key of the provisioner |
| value | [fixed64](#fixed64) |  | The amount of DUSK to stake (should correspond to the amount burned in `tx`) |
| expiration_height | [fixed64](#fixed64) |  | The block height at which this stake should unlock |
| tx | [Transaction](#rusk.Transaction) |  | Transaction underlying the contract call |

### WithdrawStakeTransaction

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bls_key | [bytes](#bytes) |  | The BLS public key of the provisioner |
| sig | [bytes](#bytes) |  | A BLS signature of the BLS public key and the deposit height of the stake to be withdrawn |
| tx | [Transaction](#rusk.Transaction) |  | Transaction underlying the contract call |

### SlashTransaction

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bls_key | [bytes](#bytes) |  | The BLS public key of the provisioner to be slashed |
| step | [uint32](#uint32) |  | The step at which the offense happened |
| round | [fixed64](#fixed64) |  | The round at which the offense happened |
| first_msg | [bytes](#bytes) |  | The first message sent by the offender |
| first_sig | [bytes](#bytes) |  | The signature of the first message |
| second_msg | [bytes](#bytes) |  | The second message sent by the offender |
| second_sig | [bytes](#bytes) |  | The signature of the second message |
| tx | [Transaction](#rusk.Transaction) |  | Transaction underlying the contract call |

### BidTransaction

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| m | [bytes](#bytes) |  | Bid M value |
| commitment | [bytes](#bytes) |  | Commitment to the value being bidded |
| encrypted_value | [bytes](#bytes) |  | The encrypted value that's being bid |
| encrypted_blinder | [bytes](#bytes) |  | The encrypted blinder |
| expiration_height | [fixed64](#fixed64) |  | The height at which this bid will unlock |
| pk | [bytes](#bytes) |  | Ed25519 Public key of the bidder |
| r | [bytes](#bytes) |  | A random scalar |
| z | [bytes](#bytes) |  | Another random scalar |
| tx | [Transaction](#rusk.Transaction) |  | Transaction underlying the contract call |

### WithdrawBidTransaction

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| commitment | [bytes](#bytes) |  | Commitment to the value being bidded |
| encrypted_value | [bytes](#bytes) |  | The encrypted value that's being bid |
| encrypted_blinder | [bytes](#bytes) |  | The encrypted blinder |
| bid | [bytes](#bytes) |  | Bid X value |
| sig | [bytes](#bytes) |  | Ed25519 signature of the bidder's public key, and the deposit height of the bid being withdrawn |
| tx | [Transaction](#rusk.Transaction) |  | Transaction underlying the contract call |

## field.proto

### CompressedPoint

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| y | [bytes](#bytes) |  |  |

### Nonce

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bs | [bytes](#bytes) |  |  |

### Scalar

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| data | [bytes](#bytes) |  |  |

## keys.proto

### PublicKey

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| a_g | [CompressedPoint](#rusk.CompressedPoint) |  |  |
| b_g | [CompressedPoint](#rusk.CompressedPoint) |  |  |

### SecretKey

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| a | [Scalar](#rusk.Scalar) |  |  |
| b | [Scalar](#rusk.Scalar) |  |  |

### ViewKey

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| a | [Scalar](#rusk.Scalar) |  |  |
| b_g | [CompressedPoint](#rusk.CompressedPoint) |  |  |

## note.proto

### DecryptedNote

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| note_type | [NoteType](#rusk.NoteType) |  |  |
| pos | [fixed64](#fixed64) |  |  |
| value | [fixed64](#fixed64) |  |  |
| nonce | [Nonce](#rusk.Nonce) |  |  |
| r_g | [CompressedPoint](#rusk.CompressedPoint) |  |  |
| pk_r | [CompressedPoint](#rusk.CompressedPoint) |  |  |
| value_commitment | [Scalar](#rusk.Scalar) |  |  |
| blinding_factor | [Scalar](#rusk.Scalar) |  |  |
| transparent_blinding_factor | [Scalar](#rusk.Scalar) |  |  |
| encrypted_blinding_factor | [bytes](#bytes) |  |  |
| transparent_value | [fixed64](#fixed64) |  |  |
| encrypted_value | [bytes](#bytes) |  |  |

### Note

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| note_type | [NoteType](#rusk.NoteType) |  |  |
| pos | [fixed64](#fixed64) |  |  |
| nonce | [Nonce](#rusk.Nonce) |  |  |
| r_g | [CompressedPoint](#rusk.CompressedPoint) |  |  |
| pk_r | [CompressedPoint](#rusk.CompressedPoint) |  |  |
| value_commitment | [Scalar](#rusk.Scalar) |  |  |
| transparent_blinding_factor | [Scalar](#rusk.Scalar) |  |  |
| encrypted_blinding_factor | [bytes](#bytes) |  |  |
| transparent_value | [fixed64](#fixed64) |  |  |
| encrypted_value | [bytes](#bytes) |  |  |

### Nullifier

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| h | [Scalar](#rusk.Scalar) |  |  |

### NoteType

| Name | Number | Description |
| ---- | ------ | ----------- |
| TRANSPARENT | 0 |  |
| OBFUSCATED | 1 |  |

## rusk.proto

### Rusk

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Echo | [EchoRequest](#rusk.EchoRequest) | [EchoResponse](#rusk.EchoResponse) | Simple echo request |
| ValidateStateTransition | [ValidateStateTransitionRequest](#rusk.ValidateStateTransitionRequest) | [ValidateStateTransitionResponse](#rusk.ValidateStateTransitionResponse) | Validate a set of transactions, returning the correct transactions |
| ExecuteStateTransition | [ExecuteStateTransitionRequest](#rusk.ExecuteStateTransitionRequest) | [ExecuteStateTransitionResponse](#rusk.ExecuteStateTransitionResponse) | Execute a set of transactions, mutating the global storage |
| GenerateScore | [GenerateScoreRequest](#rusk.GenerateSecretKeyRequest) | [GenerateScoreResponse](#rusk.GenerateScoreResponse) | Create a blind bid proof and a score |
| GenerateSecretKey | [GenerateSecretKeyRequest](#rusk.GenerateSecretKeyRequest) | [SecretKey](#rusk.SecretKey) |  |
| Keys | [SecretKey](#rusk.SecretKey) | [KeysResponse](#rusk.KeysResponse) |  |
| FullScanOwnedNotes | [ViewKey](#rusk.ViewKey) | [OwnedNotesResponse](#rusk.OwnedNotesResponse) |  |
| NewTransaction | [NewTransactionRequest](#rusk.NewTransactionRequest) | [Transaction](#rusk.Transaction) |  |
| VerifyTransaction | [Transaction](#rusk.Transaction) | [VerifyTransactionResponse](#rusk.VerifyTransactionResponse) |  |
| NewStake | [StakeTransactionRequest](#rusk.StakeTransactionRequest) | [StakeTransaction](#rusk.StakeTransaction) | |
| VerifyStake | [StakeTransaction](#rusk.StakeTransaction) | [VerifyTransactionResponse](#rusk.VerifyTransactionResponse) | |
| NewWithdrawStake | [WithdrawStakeTransactionRequest](#rusk.WithdrawStakeTransactionRequest) | [WithdrawStakeTransaction](#rusk.WithdrawStakeTransaction) | |
| VerifyWithdrawStake | [WithdrawStakeTransaction](#rusk.WithdrawStakeTransaction) | [VerifyTransactionResponse](#rusk.VerifyTransactionResponse) | |
| NewBid | [BidTransactionRequest](#rusk.BidTransactionRequest) | [BidTransaction](#rusk.BidTransaction) | |
| VerifyBid | [BidTransaction](#rusk.BidTransaction) | [VerifyTransactionResponse](#rusk.VerifyTransactionResponse) | |
| NewWithdrawBid | [WithdrawBidTransactionRequest](#rusk.WithdrawBidTransactionRequest) | [WithdrawBidTransaction](#rusk.WithdrawBidTransaction) | |
| VerifyWithdrawBid | [WithdrawBidTransaction](#rusk.WithdrawBidTransaction) | [VerifyTransactionResponse](#rusk.VerifyTransactionResponse) | |
| NewDistribute | [DistributeTransactionRequest](#rusk.DistributeTransactionRequest) | [DistributeTransaction](#rusk.DistributeTransaction) | |
| VerifyDistribute | [DistributeTransaction](#rusk.DistributeTransaction) | [VerifyTransactionResponse](#rusk.VerifyTransactionResponse) | |
| NewWithdrawFees | [WithdrawFeesTransactionRequest](#rusk.WithdrawFeesTransactionRequest) | [WithdrawFeesTransaction](#rusk.WithdrawFeesTransaction) | |
| VerifyWithdrawFees | [WithdrawFeesTransaction](#rusk.WithdrawFeesTransaction) | [VerifyTransactionResponse](#rusk.VerifyTransactionResponse) | |
| NewSlash | [SlashTransactionRequest](#rusk.SlashTransactionRequest) | [SlashTransaction](#rusk.SlashTransaction) | |
| VerifySlash | [SlashTransaction](#rusk.SlashTransaction) | [VerifyTransactionResponse](#rusk.VerifyTransactionResponse) | |

#### GenerateSecretKeyRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| b | [bytes](#bytes) |  |  |

#### KeysResponse

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| vk | [ViewKey](#rusk.ViewKey) |  |  |
| pk | [PublicKey](#rusk.PublicKey) |  |  |

#### NewTransactionRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| sk | [SecretKey](#rusk.SecretKey) |  |  |
| inputs | [TransactionInput](#rusk.TransactionInput) | repeated |  |
| outputs | [TransactionOutput](#rusk.TransactionOutput) | repeated |  |
| value | [fixed64](#fidex64) |  |  |
| fee | [fixed64](#fixed64) |  |  |
| obfuscated | [bool](#bool) |  |  |

#### SlashTransactionRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| tx | [NewTransactionRequest](#rusk.NewTransactionRequest) |  |  |

#### DistributeTransactionRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| tx | [NewTransactionRequest](#rusk.NewTransactionRequest) |  |  |

#### WithdrawFeesTransactionRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| tx | [NewTransactionRequest](#rusk.NewTransactionRequest) |  |  |

#### StakeTransactionRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bls_key | bytes | | The BLS public key used to identify the provisioner |
| tx | [NewTransactionRequest](#rusk.NewTransactionRequest) |  |  |

#### WithdrawStakeTransactionRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| tx | [NewTransactionRequest](#rusk.NewTransactionRequest) |  |  |

#### BidTransactionRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| M | bytes | | The `M` parameter obfuscating the bidden amount |
| tx | [NewTransactionRequest](#rusk.NewTransactionRequest) |  |  |

#### WithdrawBidTransactionRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| tx | [NewTransactionRequest](#rusk.NewTransactionRequest) |  |  |

#### VerifyTransactionResponse

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| verified | bool | | |

#### EchoRequest

#### EchoResponse

#### ValidateStateTransitionRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| calls | [ContractCall](#rusk.ContractCall) | repeated | List of transactions to be validated |
| current_height | [fixed64](#fixed64) | | Height of the block being validated |

#### ValidateStateTransitionResponse

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| successful_calls | [ContractCall](#rusk.ContractCall) | repeated | List of transactions which passed validation |

#### ExecuteStateTransitionRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| calls | [ContractCall](#rusk.ContractCall) | repeated | List of transactions to be executed |
| current_height | [fixed64](#fixed64) | | Height of the block being executed |

#### ExecuteStateTransitionResponse

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| success | [bool](#bool) | | Status of the execution |

#### ContractCall

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| tx | [Transaction](#rusk.Transaction) | | |
| withdraw_fee | [WithdrawFeesTransaction](#rusk.WithdrawFeesTransaction) | | |
| stake | [StakeTransaction](#rusk.StakeTransaction) | | |
| bid | [BidTransaction](#rusk.BidTransaction) | | |
| slash | [SlashTransaction](#rusk.SlashTransaction) | | |
| distribute | [DistributeTransaction](#rusk.DistributeTransaction) | | |
| withdraw_stake | [WithdrawStakeTransaction](#rusk.WithdrawStakeTransaction) | | |
| withdraw_bid | [WithdrawBidTransaction](#rusk.WithdrawBidTransaction) | | |

#### GenerateScoreRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| d | [bytes](#bytes) | | |
| k | [bytes](#bytes) | | |
| y | [bytes](#bytes) | | |
| y_inv | [bytes](#bytes) | | |
| q | [bytes](#bytes) | | |
| z | [bytes](#bytes) | | |
| seed | [bytes](#bytes) | | Previous block seed |
| bids | [bytes](#bytes) | | List of bids |
| bid_pos | [fixed64](#fixed64) | | Position of the bid to prove ownership of in `bids` |

#### GenerateScoreResponse

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| proof | [bytes](#bytes) | | Generated proof |
| score | [bytes](#bytes) | | Generated score |
| z | [bytes](#bytes) | | Identity hash |
| bids | [bytes](#bytes) | | The list of bids used to make the proof |


### Crypto

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Hash | [HashRequest](#rusk.HashRequest) | [HashResponse](#rusk.HashResponse) | Performs Poseidon hashing of up to 4 inputs |

#### HashRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| inputs | [bytes](#bytes) | repeated | The array of inputs to be passed to the hashing function |

#### HashResponse

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| hash | [field.Scalar](#field.Scalar) | | The resulting Scalar from hashing an array of byte arrays inputs |

## transaction.proto

### Transaction

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nullifiers | [Nullifier](#rusk.Nullifier) | repeated |  |
| outputs | [TransactionOutput](#rusk.TransactionOutput) | repeated |  |
| fee | [TransactionOutput](#rusk.TransactionOutput) |  |  |
| proof | [bytes](#bytes) |  |  |
| public_inputs | [Scalar](#rusk.Scalar) | repeated |  |

### TransactionInput

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| pos | [fixed64](#fixed64) |  |  |
| sk | [SecretKey](#rusk.SecretKey) |  |  |

### TransactionOutput

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| note | [Note](#rusk.Note) |  |  |
| pk | [PublicKey](#rusk.PublicKey) |  |  |
| value | [fixed64](#fixed64) |  |  |
| blinding_factor | [Scalar](#rusk.Scalar) |  |  |
