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
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"reflect"
	"encoding/binary"
//	"io"
	"sync"

	"github.com/klaytn/klaytn/common/hexutil"
	"github.com/klaytn/klaytn/crypto/sha3"
//	"github.com/klaytn/klaytn/rlp"
)

const (
	HashLength      = 32
	ExtHashLength   = 40
	AddressLength   = 20
	SignatureLength = 65
	StaticNums	= false
)

var (
	hashT    = reflect.TypeOf(Hash{})
	addressT = reflect.TypeOf(Address{})

	randBlockNum    uint32
	randIdx         uint32 = 0xffff
	extMap		map[Hash]uint32
	hashMu		sync.Mutex
)

var lastPrecompiledContractAddressHex = hexutil.MustDecode("0x00000000000000000000000000000000000003FF")

var (
	errStringLengthExceedsAddressLength = errors.New("the string length exceeds the address length (20)")
	errEmptyString                      = errors.New("empty string")
)

// Hash represents the 32 byte Keccak256 hash of arbitrary data.
type Hash [HashLength]byte

type ExtHash struct {
	Hash		Hash
	BlockNum	uint32	//`default:"2520008232"` 
	Idx		uint32	//`default:"251658240"`
}

func InitExtHash() (extH ExtHash) {
	extH.Hash = Hash{}
	extH.BlockNum = 0
	extH.Idx = 0xffff
	return extH
}
/*
func (eh ExtHash) EncodeRLP(w io.Writer) error {
	h := eh.ToHash()
	
	return rlp.Encode(w, h)
}

func (eh *ExtHash) DecodeRLP(s *rlp.Stream) error {
	var h Hash
	
        if err := s.Decode(&h); err != nil {
                return err
        }
	eh.Hash = h
	//eh.BlockNum, eh.Idx = GetRandPaddings(h.Bytes())
	eh.BlockNum, eh.Idx =  0, 0xffff
	fmt.Printf("~~~~~ DEC key = %x\n", *eh)
	return nil
}
*/

func InitBlocksIndex() {
	extMap = make(map[Hash]uint32)
	randBlockNum = 0
	randIdx = 0xffff
}

func SetBlockNum(blockNum uint32) {
	if randBlockNum == blockNum {
		return
	}
	if StaticNums {
		extMap = make(map[Hash]uint32)
		randBlockNum = 0
	} else {
		randBlockNum = blockNum
	}
	randIdx = 0xffff
	fmt.Printf("setBlockNum = %d\n", randBlockNum)
}

func GetRandPaddings(hash []byte) (block uint32, idx uint32) {
	//var ok bool
	tmpHash := BytesToHash(hash)
	if tmpHash == (Hash{}) {
		return randBlockNum, 0xffff
	}
	hashMu.Lock()
		//if idx, ok = extMap[tmpHash]; !ok {
			if !StaticNums {
				if randIdx < 0xffff {
					randIdx = 0xffff
				} else {
					randIdx+=0x10000
				}
			}
			idx = randIdx
		//	extMap[tmpHash] = randIdx
		//}
	hashMu.Unlock()

	//fmt.Printf("~~~~~ idxlog hash = %x, blocNum = %d, idx = %d\n", tmpHash, randBlockNum, idx)
	/*testHash := fmt.Sprintf("%x",tmpHash)
	//if testHash == "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421" || testHash == "21609bae207c446dffdf7f06152a661afcfff1c1dd6d8e06d1c0f5357de71221" {
	if testHash == "0000000000000000000000000000000000000000000000000000000000000000" {
		fmt.Printf("~~~~~ here\n")
	}*/
	return randBlockNum, idx
}

/*func GetRootExtHashBytes(hash []byte) []byte {
	var tmpBuf [4]byte

	reBuf := make([]byte, 8)

	binary.LittleEndian.PutUint32(tmpBuf[:], uint32(0))
	copy(reBuf[:], tmpBuf[:])
	binary.LittleEndian.PutUint32(tmpBuf[0:], uint32(0xffff))
	copy(reBuf[4:], tmpBuf[:])
	return reBuf[:]
}*/

/*
func GetExtHashBytes(hash []byte) []byte {
	var tmpBuf [4]byte

	reBuf := make([]byte, 8)

	blockNum, idx := GetRandPaddings(hash)
	binary.LittleEndian.PutUint32(tmpBuf[:], uint32(blockNum))
	copy(reBuf[:], tmpBuf[:])
	//too much?
	if idx < 0xffff {
		binary.LittleEndian.PutUint32(tmpBuf[0:], uint32(0xffff))
	} else {
		binary.LittleEndian.PutUint32(tmpBuf[0:], uint32(idx))
	}
	copy(reBuf[4:], tmpBuf[:])
	return reBuf[:]
}
*/


/*
func (h ExtHash) Bytes() []byte { 
	var hashKey [40]byte

	tmpBuf := make([]byte, 4)

	copy(hashKey[:], h.Hash[:])
	binary.LittleEndian.PutUint32(tmpBuf, uint32(h.BlockNum))
	copy(hashKey[32:], tmpBuf)
	tmpBuf[0], tmpBuf[1] = 0xff, 0xff
	binary.LittleEndian.PutUint32(tmpBuf[2:], uint16(h.Idx))
	copy(hashKey[36:], tmpBuf)

	return hashKey[:]
}

func BytesToExtHash(b []byte) ExtHash {
	var h ExtHash
	if len(b) == ExtHashLength {
		b = b[len(b)-ExtHashLength:]
		copy(h.Hash[ExtHashLength-len(b):], b)
		h.BlockNum = binary.LittleEndian.Uint32(b[32:36])
		h.Idx = binary.LittleEndian.Uint16(b[38:40])
	} else {
		if len(b) > HashLength {
			b = b[len(b)-HashLength:]
		}
		copy(h.Hash[HashLength-len(b):], b)
	}
	return h
}
*/

func (h ExtHash) Bytes() []byte { 
	hashKey := make([]byte, 40)
	tmpBuf := make([]byte, 4)

	copy(hashKey[:], h.Hash[:])
	if h.BlockNum == 0 && h.Idx == 0 {
		h.BlockNum, h.Idx = GetRandPaddings(h.Hash.Bytes())
	}
	binary.LittleEndian.PutUint32(tmpBuf, uint32(h.BlockNum))
	copy(hashKey[32:], tmpBuf)
	if h.Idx < 0xffff {
		binary.LittleEndian.PutUint32(tmpBuf, uint32(0xffff))
	} else {
		binary.LittleEndian.PutUint32(tmpBuf, uint32(h.Idx))
	}
	copy(hashKey[36:], tmpBuf)

	return hashKey[:]
}

func BytesToExtHash(b []byte) (h ExtHash) {

	if len(b) == ExtHashLength {
		b = b[len(b)-ExtHashLength:]
		copy(h.Hash[ExtHashLength-len(b):], b)
		h.BlockNum = binary.LittleEndian.Uint32(b[32:36])
		h.Idx = binary.LittleEndian.Uint32(b[36:40])
	} else {
		if len(b) > HashLength {
			b = b[len(b)-HashLength:]
		}
		copy(h.Hash[HashLength-len(b):], b)
	}
	if h.BlockNum == 0 && h.Idx == 0 {
		h.BlockNum, h.Idx = GetRandPaddings(h.Hash.Bytes())
	}
	return h

	
	//if len(b) > ExtHashLength {
	//	b = b[len(b)-ExtHashLength:]
	//}
	////copy(h.Hash[ExtHashLength-len(b):], b)
	//copy(h.Hash[:],b[:])
	//if len(b) == ExtHashLength {
	//	h.BlockNum = binary.LittleEndian.Uint32(b[32:36])
	//	h.Idx = binary.LittleEndian.Uint32(b[36:40])
	//}
	//return h
}
func BytesToRootExtHash(b []byte) (h ExtHash) {

	if len(b) == ExtHashLength {
		b = b[len(b)-ExtHashLength:]
		copy(h.Hash[ExtHashLength-len(b):], b)
	} else {
		if len(b) > HashLength {
			b = b[len(b)-HashLength:]
		}
		copy(h.Hash[HashLength-len(b):], b)
	}
	h.BlockNum = 0
	h.Idx = 0xffff
	return h
}

/*
func EmptyExtHash(h ExtHash) bool {
	return h == ExtHash{Idx:0xffff,}
}
*/

func (h ExtHash) String() string {
	return hexutil.Encode(h.Bytes())
}

func (h ExtHash) ToHash() Hash {
	return h.Hash
}

func (h ExtHash) getShardIndex(shardMask int) int {
	return h.Hash.getShardIndex(shardMask)
}

func ExtPaddingFilter(src []byte) []byte {
        srcLen := len(src)
        if srcLen > 90 {
                return src
        //} else if srcLen > 8 && src[srcLen - 6] == 0x00 && src[srcLen - 5] == 0x00 && src[srcLen-4] == 0xff && src[srcLen-3] == 0xff {
        //774728 issue } else if srcLen > 8 && src[srcLen - 5] == 0x00 && src[srcLen-4] == 0xff && src[srcLen-3] == 0xff {
        //} else if srcLen >= 40 && src[srcLen - 5] == 0x00 && src[srcLen-4] == 0xff && src[srcLen-3] == 0xff {
        //11668759 } else if srcLen >= 40 && src[srcLen-4] == 0xff && src[srcLen-3] == 0xff {
        } else if srcLen == 40 && src[srcLen-4] == 0xff && src[srcLen-3] == 0xff {
                //fmt.Printf("~~~~~ src = %x, filter = %x\n", src, src[:srcLen-8])
		reStr := make([]byte, srcLen-8)
		copy(reStr[:], src[:srcLen-8])
                return reStr
	/*
        } else if srcLen > 9 && src[srcLen - 7] == 0x00 && src[srcLen - 6] == 0x00 && src[srcLen-5] == 0xff && src[srcLen-4] == 0xff {
                //fmt.Printf("~~~~~ src = %x, filter = %x\n", src, src[:srcLen-8])
                tmpSrc := append(src[:srcLen-9], src[srcLen-1])
                return tmpSrc
	*/
        }
        //fmt.Printf("~~~~~ src = %x, same\n", src)
        return src
}

func ExtNumPaddingFilter(src []byte) []byte {
        var tmpSrc []byte

        srcLen := len(src)
        tmpSrc = make([]byte, srcLen)
        copy(tmpSrc,src)
        if srcLen > 81 {
                return tmpSrc
        } else if srcLen > 16 && tmpSrc[srcLen-1-1-4] == 0xf && tmpSrc[srcLen-7] == 0xf && tmpSrc[srcLen-8] == 0xf && tmpSrc[srcLen-9] == 0xf {
                //fmt.Printf("~~~~~ src = %x, filter = %x\n", src, src[:srcLen-8])
                reSrc := append(tmpSrc[:srcLen-1-16], tmpSrc[srcLen-1])
                return reSrc
        }
        //fmt.Printf("~~~~~ src = %x, same\n", src)
        return tmpSrc
}

func BigToExtHash(b *big.Int) ExtHash { return BytesToExtHash(b.Bytes()) }
func BigToRootExtHash(b *big.Int) ExtHash { return BytesToRootExtHash(b.Bytes()) }

func HexToExtHash(s string) ExtHash { return BytesToExtHash(FromHex(s)) }

func (h Hash) ToExtHash() (ExtH ExtHash) {
	ExtH.Hash = h
	//ExtH.BlockNum = 0x96344628
	//ExtH.Idx = 0x0f000000
	//ExtH.BlockNum = 0
	//ExtH.Idx = 0
	ExtH.BlockNum, ExtH.Idx = GetRandPaddings(ExtH.Hash.Bytes())
	return ExtH
}

func (h Hash) ToRootExtHash() (ExtH ExtHash) {
	ExtH.Hash = h
	/*  이건 나중에 enable.. 방어코드로 활용하는게 좋을듯 
	hashMu.Lock()
		extMap[h] = 0xffff
	hashMu.Unlock()
	*/
	ExtH.BlockNum = 0
	ExtH.Idx = 0xffff
	return ExtH
}

func (h Hash) InitExtHash() (ExtH ExtHash) {
	ExtH.Hash = h
	ExtH.BlockNum = 0
	ExtH.Idx = 0xffff
	return ExtH
}

// BytesToHash sets b to hash.
// If b is larger than len(h), b will be cropped from the left.
func BytesToHash(b []byte) Hash {
	var h Hash
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
	//fmt.Printf("~~~~~~~~~~ common.SetBytes11 data = %x\n", b)
	if len(b) > len(h) {
		b = b[len(b)-HashLength:]
	}
	//fmt.Printf("~~~~~~~~~~ common.SetBytes12 data = %x\n", b)

	copy(h[HashLength-len(b):], b)
	//Ethan propose.. copy(h[:], b)
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
