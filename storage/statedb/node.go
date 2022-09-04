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
// This file is derived from trie/node.go (2018/06/04).
// Modified and improved for the klaytn development.

package statedb

import (
	"fmt"
	"io"
	"strings"
	"bytes"

	"github.com/klaytn/klaytn/common"
	"github.com/klaytn/klaytn/rlp"
)

var indices = []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f", "[17]"}
//var padfind = []byte{0x28, 0x46, 0x34, 0x96, 0x00, 0x00, 0x00, 0x00, 0x0f}
var padding = []byte{0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00}

type node interface {
	fstring(string) string
	cache() (hashNode, bool)
	lenEncoded() uint16
	//Bytes()	[]byte
	//ToPreHashRLP()	node
}

type (
	fullNode struct {
		Children [17]node // Actual trie node data to encode/decode (needs custom encoder)
		flags    nodeFlag
	}
	shortNode struct {
		Key   []byte
		Val   node
		flags nodeFlag
	}

	hashNode  []byte
	valueNode []byte
	/*
	preFullNode	fullNode
	extFullNode	fullNode

	preShortNode	shortNode
	extShortNode	shortNode

	preHashNode	hashNode
	extHashNode	hashNode

	preValueNode	valueNode
	extValueNode	valueNode
	extFullNode	fullNode
	extShortNode	shortNode
	extHashNode	hashNode
	extValueNode	valueNode
	*/

)

// nilValueNode is used when collapsing internal trie nodes for hashing, since
// unset children need to serialize correctly.
var nilValueNode = valueNode(nil)

// EncodeRLP encodes a full node into the consensus RLP format.
func (n *fullNode) EncodeRLP(w io.Writer) error {
	var nodes [17]node

	for i, child := range &n.Children {
		if child != nil {
			nodes[i] = child
		} else {
			nodes[i] = nilValueNode
		}
	}
	return rlp.Encode(w, nodes)
}

/*
func (n *fullNode) ToPreHashRLP() node {
	var nodes [17]node
	var flag nodeFlag 

	for i, child := range &n.Children {
		if child != nil {
			//tmpN = n.ToExtHashRLP()
			nodes[i] = child.ToPreHashRLP()
		} else {
			nodes[i] = nil
		}
	}
	flag = n.flags
	flag.hash = common.ExtPaddingFilter(n.flags.hash)
	newF := fullNode{
		Children: nodes,
		flags: flag,
	}
	fmt.Printf("full rlp old = %v\nfull rlp new = %v\n", n, &newF)

	return &newF
}

func (n *shortNode) ToPreHashRLP() node {
	//tmpVal := modifyRLP(n.Val.(valueNode).Bytes())
	tmpVal, err := common.RlpPaddingFilter(n.Val.(valueNode).Bytes())
	if err != nil {
		tmpVal = n.Val.(valueNode).Bytes()
	}
	fmt.Printf("short rlp old = %x\nshort rlp new = %x\n",n.Val.(valueNode).Bytes(), tmpVal)
	return &extShortNode{
		Key:	common.ExtPaddingFilter(n.Key),
		Val:	toValueNode(tmpVal),
		flags:	n.flags,
	}
}
*/


//func (n *shortNode) ToPreHashRLP() node {
//	var err error
//	var tmpValue valueNode
//	serializer := account.NewAccountSerializer()
//	if err = rlp.DecodeBytes(n.Val.(valueNode).Bytes(), serializer); err == nil {
//		//err = rlp.Encode(&tmpValue, serializer)
//		fmt.Printf("~~~~~ enc shortnode rlp success1 - %v, data = %x, account = %v\n", serializer, n.Val.(valueNode).Bytes(), serializer.GetAccount())
//	} else if _, content, _, err := rlp.Split(n.Val.(valueNode).Bytes()); err == nil {
//	//} else if _, _, _, err = rlp.Split(n.Val.(valueNode).Bytes()); err == nil {
//		//err = rlp.Encode(&tmpValue, content)
//		fmt.Printf("~~~~~ enc shortnode rlp success2 - %v, data = %x\n", content, n.Val.(valueNode).Bytes())
//	} else {
//		panic("~~~~~ enc shortnode rlp unknown type")
//	}
//	return &extShortNode{
//		Key:	common.ExtPaddingFilter(n.Key),
//		Val:	tmpValue,
//		//Val:	n.Val, 
//		flags:	n.flags,
//	}
//}


func modifyRLP(src []byte) (dst []byte) {
	//srcLen := len(src)
	padLen := len(padding)
	idx := 0
	for {
		sidx := bytes.Index(src[idx:], padding)

		if sidx < 0 {
			dst = append(dst, src[idx:]...)
			break
		} else {
			dst = append(dst, src[idx:idx + sidx]...)
			dst[idx + sidx -1 - 32] -= uint8(padLen)
			idx += (sidx + padLen)
		}
	}
	return dst
}

//func (n *shortNode) ToPreHashRLP() node {
//	//var tmpValueNode valueNode
//	nVal := common.ExtPaddingFilter(n.Val.(valueNode).Bytes())
//	fmt.Printf("zzzzz org = %x, to %x\n", n.Val.(valueNode).Bytes(), nVal)
////	copy(tmpValueNode[:], nVal[:])
//	return &extShortNode{
//		Key:	common.ExtPaddingFilter(n.Key),
//		Val:	toValueNode(nVal),
//		//Val:	n.Val, 
//		flags:	n.flags,
//	}
//}

/*
func (n hashNode) ToPreHashRLP() node {
	var ext hashNode
	ext = common.ExtPaddingFilter(n)
	fmt.Printf("hash rlp old = %v\nhash rlp new = %v\n", n, ext)
	return ext
}

func (n valueNode) ToPreHashRLP() node {
	tmpVal, err := common.RlpPaddingFilter(n.Bytes())
	if err != nil {
		tmpVal = n.Bytes()
	}
	fmt.Printf("value rlp old = %v\nvalue rlp new = %v\n", n, tmpVal) 
	return toValueNode(tmpVal)
}
*/

/*
func (n *extFullNode) ToPreHashRLP() node	{ panic("this should never called function") }
func (n *extShortNode) ToPreHashRLP() node	{ panic("this should never called function") }
func (n extHashNode) ToPreHashRLP() node	{ panic("this should never called function") }
func (n extValueNode) ToPreHashRLP() node	{ panic("this should never called function") }
*/

/*
//Ethan 그냥 &로 넘겨도 되나? make로 안만들어줘도 되나?
func (ext extFullNode) toPreHashNode() (n *fullNode)	{ return &fullNode(ext) }
func (ext extShortNode) toPreHashNode() (n *shortNode)	{ return &shortNode(ext) }
func (ext extHashNode) toPreHashNode() (n hashNode)	{ return &hashNode(ext) }
func (ext extValueNode) toPreHashNode() (n hashNode)	{ return &hashNode(ext) }
*/

/*
func (n *orgShortNode) EncodeRLP(w io.Writer) error {
	n2 := &shortNodeRlp{
		Key:	rlp.ExtPaddingFilter(n.Key),
		Val:	n.Val,
		flags:	n.flags,
	}

	return rlp.Encode(w, n2)
}
*/

/*
//Ethan 220624
func (n valueNode) EncodeRLP(w io.Writer) error {
	tmpVal, err := common.RlpPaddingFilter(n.Bytes())
	if err != nil {
		tmpVal = n.Bytes()
	}
	return rlp.Encode(w, tmpVal)
}

func (n hashNode) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, rlp.ExtPaddingFilter(n))
}
*/

func (n *fullNode) copy() *fullNode   { copy := *n; return &copy }
func (n *shortNode) copy() *shortNode { copy := *n; return &copy }
func toValueNode(src []byte) valueNode {
	copy := src
	return copy
}

func toHashNode(src []byte) hashNode {
	copy := src
	return copy
}

// nodeFlag contains caching-related metadata about a node.
type nodeFlag struct {
	hash       hashNode // cached hash of the node (may be nil).
	dirty      bool     // whether the node has changes that must be written to the database.
	lenEncoded uint16   // lenEncoded caches the encoding length of the node.
}

func (n *fullNode) cache() (hashNode, bool)  { return n.flags.hash, n.flags.dirty }
func (n *shortNode) cache() (hashNode, bool) { return n.flags.hash, n.flags.dirty }
//func (n hashNode) cache() (hashNode, bool)   { return nil, true }
func (n hashNode) cache() (hashNode, bool)   { return n, false }
func (n valueNode) cache() (hashNode, bool)  { return nil, true }
/*
func (n *extFullNode) cache() (hashNode, bool)  { panic("this should never called function") }
func (n *extShortNode) cache() (hashNode, bool) { panic("this should never called function") }
func (n extHashNode) cache() (hashNode, bool)   { panic("this should never called function") }
func (n extValueNode) cache() (hashNode, bool)  { panic("this should never called function") }
*/

func (n *fullNode) lenEncoded() uint16  { return n.flags.lenEncoded }
func (n *shortNode) lenEncoded() uint16 { return n.flags.lenEncoded }
func (n hashNode) lenEncoded() uint16   { return 0 }
func (n valueNode) lenEncoded() uint16  { return 0 }
/*
func (n *extFullNode) lenEncoded() uint16  { panic("this should never called function") }
func (n *extShortNode) lenEncoded() uint16 { panic("this should never called function") }
func (n extHashNode) lenEncoded() uint16   { panic("this should never called function") }
func (n extValueNode) lenEncoded() uint16  { panic("this should never called function") }
*/

// Pretty printing.
func (n *fullNode) String() string  { return n.fstring("") }
func (n *shortNode) String() string { return n.fstring("") }
func (n hashNode) String() string   { return n.fstring("") }
func (n valueNode) String() string  { return n.fstring("") }
/*
func (n *extFullNode) String() string  { panic("this should never called function") }
func (n *extShortNode) String() string { panic("this should never called function") }
func (n extHashNode) String() string   { panic("this should never called function") }
func (n extValueNode) String() string  { panic("this should never called function") }
*/


//func (n *fullNode) Bytes() []byte  { return n[:] }
//func (n *shortNode) Bytes() []byte { return n[:] }
func (n hashNode) Bytes() []byte   { return n[:] }
func (n valueNode) Bytes() []byte  { return n[:] }
/*
func (n rawNode) Bytes() []byte  { return n[:] }
func (n rawShortNode) Bytes() []byte  { return n[:] }
func (n rawFullNode) Bytes() []byte  { return n[:] }
*/

func (n *fullNode) fstring(ind string) string {
	resp := fmt.Sprintf("[\n%s  ", ind)
	for i, node := range &n.Children {
		if node == nil {
			resp += fmt.Sprintf("%s: <nil> ", indices[i])
		} else {
			resp += fmt.Sprintf("%s: %v", indices[i], node.fstring(ind+"  "))
		}
	}
	return resp + fmt.Sprintf("\n%s] ", ind)
}
func (n *shortNode) fstring(ind string) string {
	return fmt.Sprintf("{%x: %v} ", n.Key, n.Val.fstring(ind+"  "))
}
func (n hashNode) fstring(ind string) string {
	return fmt.Sprintf("<%x> ", []byte(n))
}
func (n valueNode) fstring(ind string) string {
	return fmt.Sprintf("%x ", []byte(n))
}

/*
func (n *extFullNode) fstring(string) string  { panic("this should never called function") }
func (n *extShortNode) fstring(string) string { panic("this should never called function") }
func (n extHashNode) fstring(string) string   { panic("this should never called function") }
func (n extValueNode) fstring(string) string  { panic("this should never called function") }
*/

func mustDecodeNode(hash, buf []byte) node {
	n, err := decodeNode(hash, buf)
	if err != nil {
		panic(fmt.Sprintf("node %x: %v", hash, err))
	}
	return n
}

// decodeNode parses the RLP encoding of a trie node.
func decodeNode(hash, buf []byte) (node, error) {
	if len(buf) == 0 {
		return nil, io.ErrUnexpectedEOF
	}
	elems, _, err := rlp.SplitList(buf)
	if err != nil {
		return nil, fmt.Errorf("decode error: %v", err)
	}
	switch c, _ := rlp.CountValues(elems); c {
	case 2:
		n, err := decodeShort(hash, elems)
		return n, wrapError(err, "short")
	case 17:
		n, err := decodeFull(hash, elems)
		return n, wrapError(err, "full")
	default:
		return nil, fmt.Errorf("invalid number of list elements: %v", c)
	}
}

func decodeShort(hash, elems []byte) (node, error) {
	kbuf, rest, err := rlp.SplitString(elems)
	if err != nil {
		return nil, err
	}
	flag := nodeFlag{hash: hash}
	/*
	//key := compactToHex(kbuf)
	//Ethan deocode가 잘 되면 이부분이 있을 필요가 없음//
	tmpKey := common.ExtNumPaddingFilter(compactToHex(kbuf))
	tmpKeyLen := len(tmpKey)
	extPad := []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xf, 0xf, 0xf, 0xf, 0x0, 0x0, 0x0, 0x0, 0x10}
	key := append(tmpKey[:tmpKeyLen-1], extPad...)
	*/
	key := compactToHex(kbuf)
	if hasTerm(key) {
		// value node
		val, _, err := rlp.SplitString(rest)
		if err != nil {
			return nil, fmt.Errorf("invalid value node: %v", err)
		}
		return &shortNode{key, append(valueNode{}, val...), flag}, nil
	}
	r, _, err := decodeRef(rest)
	if err != nil {
		return nil, wrapError(err, "val")
	}
	return &shortNode{key, r, flag}, nil
}

func decodeFull(hash, elems []byte) (*fullNode, error) {
	n := &fullNode{flags: nodeFlag{hash: hash}}
	for i := 0; i < 16; i++ {
		cld, rest, err := decodeRef(elems)
		if err != nil {
			return n, wrapError(err, fmt.Sprintf("[%d]", i))
		}
		n.Children[i], elems = cld, rest
	}
	val, _, err := rlp.SplitString(elems)
	if err != nil {
		return n, err
	}
	if len(val) > 0 {
		n.Children[16] = append(valueNode{}, val...)
	}
	return n, nil
}

const hashLen = len(common.Hash{})

func decodeRef(buf []byte) (node, []byte, error) {
	kind, val, rest, err := rlp.Split(buf)
	if err != nil {
		return nil, buf, err
	}
	switch {
	case kind == rlp.List:
		// 'embedded' node reference. The encoding must be smaller
		// than a hash in order to be valid.
		if size := len(buf) - len(rest); size > hashLen {
			err := fmt.Errorf("oversized embedded node (size is %d bytes, want size < %d)", size, hashLen)
			return nil, buf, err
		}
		n, err := decodeNode(nil, buf)
		return n, rest, err
	case kind == rlp.String && len(val) == 0:
		// empty node
		return nil, rest, nil
	//Ethan 헷갈리네....
	//case kind == rlp.String && len(val) == 32:
	//case kind == rlp.String && len(val) == common.HashLength:
	case kind == rlp.String && len(val) == common.ExtHashLength:
		return append(hashNode{}, val...), rest, nil
	default:
		return nil, nil, fmt.Errorf("invalid RLP string size %d (want 0 or %d)", len(val), common.ExtHashLength)
	}
}

// wraps a decoding error with information about the path to the
// invalid child node (for debugging encoding issues).
type decodeError struct {
	what  error
	stack []string
}

func wrapError(err error, ctx string) error {
	if err == nil {
		return nil
	}
	if decErr, ok := err.(*decodeError); ok {
		decErr.stack = append(decErr.stack, ctx)
		return decErr
	}
	return &decodeError{err, []string{ctx}}
}

func (err *decodeError) Error() string {
	return fmt.Sprintf("%v (decode path: %s)", err.what, strings.Join(err.stack, "<-"))
}
