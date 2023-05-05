// Modifications Copyright 2018 The klaytn Authors
// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.
//
// This file is derived from common/types.go (2018/06/04).
// Modified and improved for the klaytn development.

package common

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"reflect"
	"runtime/debug"
	"sync"
	"time"

	"github.com/klaytn/klaytn/common/hexutil"
	"github.com/klaytn/klaytn/crypto/sha3"
)

const (
	HashLength = 32

	ExtHashLength = 38 // = HashLength + ExtPadLength
	ExtPadLength  = 6  // = ExtIdxLength + ExtSigLength + ExtCSLength

	AddressLength   = 20
	SignatureLength = 65
)

var (
	hashT    = reflect.TypeOf(Hash{})
	addressT = reflect.TypeOf(Address{})

	hashMu sync.Mutex

	lastPrecompiledContractAddressHex          = hexutil.MustDecode("0x00000000000000000000000000000000000003FF")
	CntIdx                              uint64 = uint64(time.Now().UnixNano()) - 500000000
	RootByte                                   = hexutil.MustDecode("0x000000000011")
	ZeroByte                                   = hexutil.MustDecode("0x000000000000")
	LegacyByte                                 = hexutil.MustDecode("0x000000000045")
	errStringLengthExceedsAddressLength        = errors.New("the string length exceeds the address length (20)")
	errEmptyString                             = errors.New("empty string")
	ExtHashDisableFlag                  bool   = true
	DelHashFlag                         bool   = false
)

func init() {
	if ExtHashDisableFlag {
		LegacyByte = RootByte
	}
}

// Hash represents the 32 byte Keccak256 hash of arbitrary data.
type (
	Hash    [HashLength]byte
	ExtHash [ExtHashLength]byte
)

// ---- hash - 32 byte ----, ---- idx (4 byte) ----, ---- signature (1 byte) ----, ---- checkSum (3byte) ----
// root ExtHash ...32byte...0000000045000000

func InitExtHash() (extH ExtHash) {
	copy(extH[HashLength:], RootByte)
	return extH
}

func GetExtHashPadBytes(hash []byte) (padding []byte) {
	if ExtHashDisableFlag {
		return RootByte
	}
	if len(hash) == ExtHashLength {
		return hash[HashLength:]
	}
	return getNewExtPadding(hash)
}

func ExtPaddingFilter(src []byte) []byte {
	if len(src) == ExtHashLength {
		return src[:HashLength]
	}
	return src
}

// to do : getNewExtPadding, CheckExtPadding tuning
func getNewExtPadding(hash []byte) (rePadding []byte) {
	rePadding = make([]byte, ExtPadLength+8)

	hashMu.Lock()
	localIdx := CntIdx
	CntIdx += 0xffff
	hashMu.Unlock()

	binary.BigEndian.PutUint64(rePadding[:], localIdx)
	return rePadding[:ExtPadLength]
}

func (h ExtHash) Bytes() []byte {
	return h[:]
}

func BytesToExtHash(b []byte) (h ExtHash) {
	bLen := len(b)
	if bLen == ExtHashLength {
		copy(h[:ExtHashLength], b)
	} else if bLen == HashLength {
		copy(h[:HashLength], b)
	} else {
		if bLen > HashLength {
			b = b[bLen-HashLength:]
			bLen = len(b)
		}
		copy(h[HashLength-bLen:], b)
	}
	if bytes.Equal(h[HashLength:], ZeroByte) {
		copy(h[HashLength:], GetExtHashPadBytes(b))
	}
	return h
}

func BytesToRootExtHash(b []byte) (h ExtHash) {
	bLen := len(b)
	if bLen == ExtHashLength {
		copy(h[:ExtHashLength], b)
	} else if bLen == ExtHashLength+1 {
		copy(h[:ExtHashLength], b[1:])
	} else if bLen == HashLength {
		copy(h[:HashLength], b)
		copy(h[HashLength:], RootByte) // Ethan Defence code by CodeHash issue
	} else if bLen == HashLength+1 {
		copy(h[:HashLength], b[1:])
		copy(h[HashLength:], RootByte) // Ethan Defence code by CodeHash issue
	} else {
		if bLen > HashLength {
			b = b[bLen-HashLength:]
		}
		copy(h[HashLength-bLen:], b)
		copy(h[HashLength:], RootByte) // Ethan Defence code by CodeHash issue
	}
	// Ethan Defence code by CodeHash issue	//copy(h[HashLength:], RootByte)
	return h
}

func BytesLegacyToExtHash(b []byte) (h ExtHash) {
	bLen := len(b)
	if bLen == ExtHashLength {
		copy(h[:ExtHashLength], b)
	} else if bLen == HashLength {
		copy(h[:HashLength], b)
	} else {
		if bLen > HashLength {
			b = b[bLen-HashLength:]
		}
		copy(h[HashLength-bLen:], b)
	}
	copy(h[HashLength:], LegacyByte)
	return h
}

func (h ExtHash) String() string {
	return fmt.Sprintf("%s", h.Bytes())
}

func (h ExtHash) ToHash() (reH Hash) {
	copy(reH[:HashLength], h[:HashLength])
	return reH
}

func (h ExtHash) ToRoot() (reH ExtHash) {
	copy(reH[:HashLength], h[:HashLength])
	copy(reH[HashLength:], RootByte)
	return reH
}

func (h ExtHash) ToLegacy() (reH ExtHash) {
	copy(reH[:HashLength], h[:HashLength])
	copy(reH[HashLength:], LegacyByte)
	debug.PrintStack()
	return reH
}

func (h ExtHash) getShardIndex(shardMask int) int {
	data1 := int(h[HashLength-1]) + int(h[0])
	data2 := int(h[HashLength-2]) + int(h[1])
	return ((data2 << 8) + data1) & shardMask
}

func (h ExtHash) Hex() string { return hexutil.Encode(h[:]) }

func BigToExtHash(b *big.Int) ExtHash     { return BytesToExtHash(b.Bytes()) }
func BigToRootExtHash(b *big.Int) ExtHash { return BytesToRootExtHash(b.Bytes()) }
func HexToExtHash(s string) ExtHash       { return BytesToExtHash(FromHex(s)) }

func (h Hash) ToExtHash() (ExtH ExtHash) {
	copy(ExtH[:HashLength], h[:])
	copy(ExtH[HashLength:], GetExtHashPadBytes(h.Bytes()))
	return ExtH
}

func (h Hash) ToRootExtHash() (ExtH ExtHash) {
	copy(ExtH[:HashLength], h[:])
	copy(ExtH[HashLength:], RootByte)
	return ExtH
}

func (h Hash) LegacyToExtHash() (ExtH ExtHash) {
	copy(ExtH[:HashLength], h[:])
	copy(ExtH[HashLength:], LegacyByte)
	debug.PrintStack()
	return ExtH
}

func (h Hash) InitExtHash() (ExtH ExtHash) {
	return h.ToRootExtHash()
}

// BytesToHash sets b to hash.
// If b is larger than len(h), b will be cropped from the left.
func BytesToHash(b []byte) (h Hash) {
	h.SetBytes(b)
	return h
}

// BigToHash sets byte representation of b to hash.
// If b is larger than len(h), b will be cropped from the left.
func BigToHash(b *big.Int) Hash { return BytesToHash(b.Bytes()) }

// HexToHash sets byte representation of s to hash.
// If b is larger than len(h), b will be cropped from the left.
func HexToHash(s string) Hash { return BytesToHash(FromHex(s)) }

// Bytes gets the byte representation of the underlying hash.
func (h Hash) Bytes() []byte { return h[:] }

// Big converts a hash to a big integer.
func (h Hash) Big() *big.Int { return new(big.Int).SetBytes(h[:]) }

// Hex converts a hash to a hex string.
func (h Hash) Hex() string { return hexutil.Encode(h[:]) }

// TerminalString implements log.TerminalStringer, formatting a string for console
// output during logging.
func (h Hash) TerminalString() string {
	return fmt.Sprintf("%x…%x", h[:3], h[29:])
}

// String implements the stringer interface and is used also by the logger when
// doing full logging into a file.
func (h Hash) String() string {
	return h.Hex()
}

// Format implements fmt.Formatter, forcing the byte slice to be formatted as is,
// without going through the stringer interface used for logging.
func (h Hash) Format(s fmt.State, c rune) {
	fmt.Fprintf(s, "%"+string(c), h[:])
}

// UnmarshalText parses a hash in hex syntax.
func (h *Hash) UnmarshalText(input []byte) error {
	return hexutil.UnmarshalFixedText("Hash", input, h[:])
}

// UnmarshalJSON parses a hash in hex syntax.
func (h *Hash) UnmarshalJSON(input []byte) error {
	return hexutil.UnmarshalFixedJSON(hashT, input, h[:])
}

// MarshalText returns the hex representation of h.
func (h Hash) MarshalText() ([]byte, error) {
	return hexutil.Bytes(h[:]).MarshalText()
}

// SetBytes sets the hash to the value of b.
// If b is larger than len(h), b will be cropped from the left.
func (h *Hash) SetBytes(b []byte) {
	if len(b) > len(h) {
		b = b[len(b)-HashLength:]
	}

	copy(h[HashLength-len(b):], b)
}

// Generate implements testing/quick.Generator.
func (h Hash) Generate(rand *rand.Rand, size int) reflect.Value {
	m := rand.Intn(len(h))
	for i := len(h) - 1; i > m; i-- {
		h[i] = byte(rand.Uint32())
	}
	return reflect.ValueOf(h)
}

// getShardIndex returns the index of the shard.
// The address is arranged in the front or back of the array according to the initialization method.
// And the opposite is zero. In any case, to calculate the various shard index values,
// add both values and shift to calculate the shard index.
func (h Hash) getShardIndex(shardMask int) int {
	data1 := int(h[HashLength-1]) + int(h[0])
	data2 := int(h[HashLength-2]) + int(h[1])
	return ((data2 << 8) + data1) & shardMask
}

func EmptyHash(h Hash) bool {
	return h == Hash{}
}

// UnprefixedHash allows marshaling a Hash without 0x prefix.
type UnprefixedHash Hash

// UnmarshalText decodes the hash from hex. The 0x prefix is optional.
func (h *UnprefixedHash) UnmarshalText(input []byte) error {
	return hexutil.UnmarshalFixedUnprefixedText("UnprefixedHash", input, h[:])
}

// MarshalText encodes the hash as hex.
func (h UnprefixedHash) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(h[:])), nil
}

/////////// Address

// Address represents the 20 byte address of a Klaytn account.
type Address [AddressLength]byte

func EmptyAddress(a Address) bool {
	return a == Address{}
}

// BytesToAddress returns Address with value b.
// If b is larger than len(h), b will be cropped from the left.
func BytesToAddress(b []byte) Address {
	var a Address
	a.SetBytes(b)
	return a
}
func StringToAddress(s string) Address { return BytesToAddress([]byte(s)) }

// BigToAddress returns Address with byte values of b.
// If b is larger than len(h), b will be cropped from the left.
func BigToAddress(b *big.Int) Address { return BytesToAddress(b.Bytes()) }

// HexToAddress returns Address with byte values of s.
// If s is larger than len(h), s will be cropped from the left.
func HexToAddress(s string) Address { return BytesToAddress(FromHex(s)) }

// IsPrecompiledContractAddress returns true if the input address is in the range of precompiled contract addresses.
func IsPrecompiledContractAddress(addr Address) bool {
	if bytes.Compare(addr.Bytes(), lastPrecompiledContractAddressHex) > 0 || addr == (Address{}) {
		return false
	}
	return true
}

// IsHexAddress verifies whether a string can represent a valid hex-encoded
// Klaytn address or not.
func IsHexAddress(s string) bool {
	if hasHexPrefix(s) {
		s = s[2:]
	}
	return len(s) == 2*AddressLength && isHex(s)
}

// Bytes gets the string representation of the underlying address.
func (a Address) Bytes() []byte { return a[:] }

// Hash converts an address to a hash by left-padding it with zeros.
func (a Address) Hash() Hash { return BytesToHash(a[:]) }

// Hex returns an EIP55-compliant hex string representation of the address.
func (a Address) Hex() string {
	unchecksummed := hex.EncodeToString(a[:])
	sha := sha3.NewKeccak256()
	sha.Write([]byte(unchecksummed))
	hash := sha.Sum(nil)

	result := []byte(unchecksummed)
	for i := 0; i < len(result); i++ {
		hashByte := hash[i/2]
		if i%2 == 0 {
			hashByte = hashByte >> 4
		} else {
			hashByte &= 0xf
		}
		if result[i] > '9' && hashByte > 7 {
			result[i] -= 32
		}
	}
	return "0x" + string(result)
}

// String implements fmt.Stringer.
func (a Address) String() string {
	return a.Hex()
}

// Format implements fmt.Formatter, forcing the byte slice to be formatted as is,
// without going through the stringer interface used for logging.
func (a Address) Format(s fmt.State, c rune) {
	fmt.Fprintf(s, "%"+string(c), a[:])
}

// SetBytes sets the address to the value of b.
// If b is larger than len(a) it will panic.
func (a *Address) SetBytes(b []byte) {
	if len(b) > len(a) {
		b = b[len(b)-AddressLength:]
	}
	copy(a[AddressLength-len(b):], b)
}

// SetBytesFromFront sets the address to the value of b.
// If len(b) is larger, take AddressLength bytes from front.
func (a *Address) SetBytesFromFront(b []byte) {
	if len(b) > AddressLength {
		b = b[:AddressLength]
	}
	copy(a[:], b)
}

// MarshalText returns the hex representation of a.
func (a Address) MarshalText() ([]byte, error) {
	return hexutil.Bytes(a[:]).MarshalText()
}

// UnmarshalText parses a hash in hex syntax.
func (a *Address) UnmarshalText(input []byte) error {
	return hexutil.UnmarshalFixedText("Address", input, a[:])
}

// UnmarshalJSON parses a hash in hex syntax.
func (a *Address) UnmarshalJSON(input []byte) error {
	return hexutil.UnmarshalFixedJSON(addressT, input, a[:])
}

// getShardIndex returns the index of the shard.
// The address is arranged in the front or back of the array according to the initialization method.
// And the opposite is zero. In any case, to calculate the various shard index values,
// add both values and shift to calculate the shard index.
func (a Address) getShardIndex(shardMask int) int {
	data1 := int(a[AddressLength-1]) + int(a[0])
	data2 := int(a[AddressLength-2]) + int(a[1])
	return ((data2 << 8) + data1) & shardMask
}

// UnprefixedAddress allows marshaling an Address without 0x prefix.
type UnprefixedAddress Address

// UnmarshalText decodes the address from hex. The 0x prefix is optional.
func (a *UnprefixedAddress) UnmarshalText(input []byte) error {
	return hexutil.UnmarshalFixedUnprefixedText("UnprefixedAddress", input, a[:])
}

// MarshalText encodes the address as hex.
func (a UnprefixedAddress) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(a[:])), nil
}

type ConnType int

const ConnTypeUndefined ConnType = -1

const (
	CONSENSUSNODE ConnType = iota
	ENDPOINTNODE
	PROXYNODE
	BOOTNODE
	UNKNOWNNODE // For error case
)

func (ct ConnType) Valid() bool {
	if int(ct) > 255 {
		return false
	}
	return true
}

func (ct ConnType) String() string {
	s := fmt.Sprintf("%d", int(ct))
	return s
}
