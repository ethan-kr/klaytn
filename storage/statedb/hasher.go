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
// This file is derived from trie/hasher.go (2018/06/04).
// Modified and improved for the klaytn development.

package statedb

import (
	"hash"
	"sync"
	"fmt"
	"reflect"
	"strings"
	//"runtime/debug"

	"github.com/klaytn/klaytn/common"
	"github.com/klaytn/klaytn/crypto/sha3"
	"github.com/klaytn/klaytn/rlp"
)

type hasher struct {
	tmp    sliceBuffer
	sha    keccakState
	onleaf LeafCallback
}

// keccakState wraps sha3.state. In addition to the usual hash methods, it also supports
// Read to get a variable amount of data from the hash state. Read is faster than Sum
// because it doesn't copy the internal state, but also modifies the internal state.
type keccakState interface {
	hash.Hash
	Read([]byte) (int, error)
}

type sliceBuffer []byte

func (b *sliceBuffer) Write(data []byte) (n int, err error) {
	*b = append(*b, data...)
	return len(data), nil
}

func (b *sliceBuffer) Reset() {
	*b = (*b)[:0]
}

// hashers live in a global db.
var hasherPool = sync.Pool{
	New: func() interface{} {
		return &hasher{
			tmp: make(sliceBuffer, 0, 550), // cap is as large as a full fullNode.
			sha: sha3.NewKeccak256().(keccakState),
		}
	},
}

func newHasher(onleaf LeafCallback) *hasher {
	h := hasherPool.Get().(*hasher)
	h.onleaf = onleaf
	return h
}

func returnHasherToPool(h *hasher) {
	hasherPool.Put(h)
}

// hash collapses a node down into a hash node, also returning a copy of the
// original node initialized with the computed hash to replace the original one.
func (h *hasher) hash(n node, db *Database, force bool) (node, node) {
	// If we're not storing the node, just hashing, use available cached data
	if hash, dirty := n.cache(); hash != nil {
		if db == nil {
			return hash, n
		}
		if !dirty {
			switch n.(type) {
			case *fullNode, *shortNode:
				return hash, hash
			default:
				return hash, n
			}
		}
	}
	// Trie not processed yet or needs storage, walk the children
	collapsed, cached := h.hashChildren(n, db)
	hashed, lenEncoded, extHashed := h.store(collapsed, db, force, false)
	// Cache the hash of the node for later reuse and remove
	// the dirty flag in commit mode. It's fine to assign these values directly
	// without copying the node first because hashChildren copies it.
	//cachedHash, _ := hashed.(hashNode)
	//extCachedHash := common.BytesToExtHash(cachedHash.Bytes()).Bytes()
	extCachedHash := extHashed.Bytes()
        cachedHash, ok := hashed.(hashNode)
        if extHashed.ToHash() == (common.Hash{}) && ok {
		extCachedHash = common.BytesToExtHash(cachedHash.Bytes()).Bytes()
		//fmt.Printf("~~~~~ new Hash? cached = %x, newhasehd = %x\n", cachedHash.Bytes(), extCachedHash)
	}
	switch cn := cached.(type) {
	case *shortNode:
		//cn.flags.hash = cachedHash
		//cn.flags.hash = common.BytesToExtHash(cachedHash.Bytes()).Bytes()
		if ok {
                        cn.flags.hash = extCachedHash
                } else {
                        cn.flags.hash = cachedHash
                }
		cn.flags.lenEncoded = lenEncoded
		if db != nil {
			cn.flags.dirty = false
		}
	case *fullNode:
		//cn.flags.hash = cachedHash
		//cn.flags.hash = common.BytesToExtHash(cachedHash.Bytes()).Bytes()
		if ok {
                        cn.flags.hash = extCachedHash
                } else {
                        cn.flags.hash = cachedHash
                }
		cn.flags.lenEncoded = lenEncoded
		if db != nil {
			cn.flags.dirty = false
		}
	}
	//220619 return hashed, cached
	//return toHashNode(common.BytesToExtHash(hashed.(hashNode).Bytes()).Bytes()), cached
	typeStr := fmt.Sprintf("%v", reflect.TypeOf(hashed))
	valueStr := fmt.Sprintf("%s", hashed)
	if strings.Index(valueStr, "00000000000000000000000") > 0 {
		fmt.Printf("~~~~~ here 0\n")
	}
	//fmt.Printf("~~~~~ shortNode1 Issue, type=%s, value=%s\n", typeStr, hashed)
	
	if strings.Index(typeStr, "shortNode") > 0 {
		//fmt.Printf("~~~~~ shortNode Issue, type=%s, value=%x\n", typeStr, hashed)
		return hashed, cached
	} else if strings.Index(typeStr, "hashNode") > 0 {
		return toHashNode(extCachedHash), cached
	} else if strings.Index(typeStr, "valueNode") > 0 {
		return valueNode(extCachedHash), cached
	} else {
		//return hashNode(common.BytesToExtHash(hashed.(hashNode).Bytes()).Bytes()), cached
		panic(fmt.Sprintf("node process not defind : node type = %s", typeStr))
	}
}

func (h *hasher) hashRoot(n node, db *Database, force bool, extRootFlag bool) (node, node) {
	// If we're not storing the node, just hashing, use available cached data
	if hash, dirty := n.cache(); hash != nil {
		if db == nil {
			return hash, n
		}
		if !dirty {
			switch n.(type) {
			case *fullNode, *shortNode:
				return hash, hash
			default:
				return hash, n
			}
		}
	}
	// Trie not processed yet or needs storage, walk the children
	collapsed, cached := h.hashChildrenFromRoot(n, db)
	hashed, lenEncoded, extHashed := h.store(collapsed, db, force, extRootFlag)
	// Cache the hash of the node for later reuse and remove
	// the dirty flag in commit mode. It's fine to assign these values directly
	// without copying the node first because hashChildren copies it.
	//cachedHash, _ := hashed.(hashNode)
	//extCachedHash := common.BytesToRootExtHash(cachedHash.Bytes()).Bytes()
	extCachedHash := extHashed.Bytes()
        cachedHash, ok := hashed.(hashNode)
        if extHashed.ToHash() == (common.Hash{}) && ok {
		if extRootFlag {
			extCachedHash = common.BytesToRootExtHash(cachedHash.Bytes()).Bytes()
		} else {
			extCachedHash = common.BytesToExtHash(cachedHash.Bytes()).Bytes()
		}
	}
	switch cn := cached.(type) {
	case *shortNode:
		//cn.flags.hash = cachedHash
		//cn.flags.hash = common.BytesToExtHash(cachedHash.Bytes()).Bytes()	//220619
		//cn.flags.hash = common.BytesToHash(cachedHash).ToRootExtHash().Bytes() //pre
		if ok {
                        cn.flags.hash = extCachedHash
                } else {
                        cn.flags.hash = cachedHash
                }
		cn.flags.lenEncoded = lenEncoded
		if db != nil {
			cn.flags.dirty = false
		}
	case *fullNode:
		//cn.flags.hash = cachedHash
		//cn.flags.hash = common.BytesToExtHash(cachedHash.Bytes()).Bytes()	//220619
		//cn.flags.hash = common.BytesToHash(cachedHash).ToRootExtHash().Bytes() //pre
		if ok {
                        cn.flags.hash = extCachedHash
                } else {
                        cn.flags.hash = cachedHash
                }
		cn.flags.lenEncoded = lenEncoded
		if db != nil {
			cn.flags.dirty = false
		}
	}
	//220619 return hashed, cached
	//return toHashNode(common.BytesToExtHash(hashed.(hashNode).Bytes()).Bytes()), cached
	typeStr := fmt.Sprintf("%v", reflect.TypeOf(hashed))
	//fmt.Printf("~~~~~ shortNode2 Issue, type=%s, value=%s\n", typeStr, hashed)
	if strings.Index(typeStr, "shortNode") > 0 {
		//fmt.Printf("~~~~~ shortNode Issue, type=%s, value=%x\n", typeStr, hashed)
		return hashed, cached
	} else if strings.Index(typeStr, "hashNode") > 0 {
		return toHashNode(extCachedHash), cached
	} else if strings.Index(typeStr, "valueNode") > 0 {
		//fmt.Printf("~~~~~ shortNode Issue, type=%s, value=%x\n", typeStr, hashed)
		return valueNode(extCachedHash), cached
	} else {
		//return hashNode(common.BytesToExtHash(hashed.(hashNode).Bytes()).Bytes()), cached
		panic(fmt.Sprintf("node process not defind : node type = %s", typeStr))
	}
}

// hashChildren replaces the children of a node with their hashes if the encoded
// size of the child is larger than a hash, returning the collapsed node as well
// as a replacement for the original node with the child hashes cached in.
func (h *hasher) hashChildren(original node, db *Database) (node, node) {
	switch n := original.(type) {
	case *shortNode:
		// Hash the short node's child, caching the newly hashed subtree
		collapsed, cached := n.copy(), n.copy()
		collapsed.Key = hexToCompact(n.Key)
		cached.Key = common.CopyBytes(n.Key)

		if _, ok := n.Val.(valueNode); !ok {
			collapsed.Val, cached.Val = h.hash(n.Val, db, false)
		}
		return collapsed, cached

	case *fullNode:
		// Hash the full node's children, caching the newly hashed subtrees
		collapsed, cached := n.copy(), n.copy()

		for i := 0; i < 16; i++ {
			if n.Children[i] != nil {
				collapsed.Children[i], cached.Children[i] = h.hash(n.Children[i], db, false)
			}
		}
		cached.Children[16] = n.Children[16]
		return collapsed, cached

	default:
		// Value and hash nodes don't have children so they're left as were
		return n, original
	}
}

type hashResult struct {
	index     int
	collapsed node
	cached    node
}

func (h *hasher) hashChildrenFromRoot(original node, db *Database) (node, node) {
	switch n := original.(type) {
	case *shortNode:
		// Hash the short node's child, caching the newly hashed subtree
		collapsed, cached := n.copy(), n.copy()
		collapsed.Key = hexToCompact(n.Key)
		cached.Key = common.CopyBytes(n.Key)

		if _, ok := n.Val.(valueNode); !ok {
			collapsed.Val, cached.Val = h.hash(n.Val, db, false)
		}
		return collapsed, cached

	case *fullNode:
		// Hash the full node's children, caching the newly hashed subtrees
		collapsed, cached := n.copy(), n.copy()

		hashResultCh := make(chan hashResult, 16)
		numRootChildren := 0
		for i := 0; i < 16; i++ {
			if n.Children[i] != nil {
				numRootChildren++
				go func(i int, n node) {
					childHasher := newHasher(h.onleaf)
					defer returnHasherToPool(childHasher)
					collapsedFromChild, cachedFromChild := childHasher.hash(n, db, false)
					hashResultCh <- hashResult{i, collapsedFromChild, cachedFromChild}
				}(i, n.Children[i])
			}
		}

		for i := 0; i < numRootChildren; i++ {
			hashResult := <-hashResultCh
			idx := hashResult.index
			collapsed.Children[idx], cached.Children[idx] = hashResult.collapsed, hashResult.cached
		}

		cached.Children[16] = n.Children[16]
		return collapsed, cached

	default:
		// Value and hash nodes don't have children so they're left as were
		return n, original
	}
}

// store hashes the node n and if we have a storage layer specified, it writes
// the key/value pair to it and tracks any node->child references as well as any
// node->external trie references.
func (h *hasher) store(n node, db *Database, force, rootFlag bool) (node, uint16, common.ExtHash) {
	var tmpHash common.ExtHash
	valueStr := fmt.Sprintf("%s", n)
	if strings.Index(valueStr, "0000000000000000000000000000000000000000000000000000000000000000") > 0 {
		fmt.Printf("~~~~~ here 3\n")
	}
	// Don't store hashes or empty nodes.
	if _, isHash := n.(hashNode); n == nil || isHash {
		/*if n != nil && !rootFlag {
			tmpHash = common.BytesToHash(n.(hashNode).Bytes())
		}*/
		return n, 0, tmpHash
	}	//Ethan 캐시를 없애야 새로 할당 하기 때문에
	hash, _ := n.cache()
	lenEncoded := n.lenEncoded()
	//hash = nil
	//lenEncoded = 0
	if hash == nil || lenEncoded == 0 {
		// Generate the RLP encoding of the node
		h.tmp.Reset()
		//tmpN := n.ToPreHashRLP()
		//if err := rlp.Encode(&h.tmp, tmpN); err != nil {
		if err := rlp.Encode(&h.tmp, n); err != nil {
			panic("extEncode error: " + err.Error())
		}
		//htmp := h.tmp
		//h.tmp.Reset()
		//h.tmp = common.RlpPaddingFilter(htmp)
		lenEncoded = uint16(len(h.tmp))

		//fmt.Printf("===== n = %v, type = %v, h.tmp = %x, len = %d\n", n, reflect.TypeOf(n), h.tmp, lenEncoded )
	}
	if lenEncoded < 32 && !force {
		return n, lenEncoded, tmpHash // Nodes smaller than 32 bytes are stored inside their parent
	}
	if hash == nil {
		hash = h.makeHashNode(h.tmp)
		//fmt.Printf("~~~~~ hash2= %x, data = %x\n", hash, h.tmp) 

	} else {
		fmt.Printf("===== not hashed(cached) = %v\n", hash)
	}
	if db != nil {
		// We are pooling the trie nodes into an intermediate memory cache
		//byteHash := hash
		if rootFlag {
			tmpHash = common.BytesToRootExtHash(hash)
		} else {
			tmpHash = common.BytesToExtHash(hash)
		}
		//fmt.Printf("~~~~~ store bytelen = %d, byteHash = %x, ExtHash = %x\n", len(byteHash),  byteHash, hash)
		//fmt.Printf("~~~~~ store bytelen = %d, ExtHash = %s\n", lenEncoded,  tmpHash)

		db.lock.Lock()
		db.insert(tmpHash, lenEncoded, n)
		db.lock.Unlock()

		// Track external references from account->storage trie
		if h.onleaf != nil {
			switch n := n.(type) {
			case *shortNode:
				if child, ok := n.Val.(valueNode); ok {
					h.onleaf(child, tmpHash, 0)
				}
			case *fullNode:
				for i := 0; i < 16; i++ {
					if child, ok := n.Children[i].(valueNode); ok {
						h.onleaf(child, tmpHash, 0)
					}
				}
			}
		}
	}
	return hash, lenEncoded, tmpHash
}

func (h *hasher) makeHashNode(data []byte) hashNode {
	//ethan_find(data)
	n := make(hashNode, h.sha.Size())
	h.sha.Reset()
	//h.sha.Write(data)
	tmpData, err := common.RlpPaddingFilter(data)
	if err == nil {
		h.sha.Write(tmpData)
	} else {
		tmpData = rlp.ExtPaddingFilter(data)
		h.sha.Write(tmpData)
	}
	h.sha.Read(n)
	//fmt.Printf("~~~~~ hash1= %v, data = %.20x(..%d)\n", n, data, len(data))
	//fmt.Printf("~~~~~ hash1= %v, data = %x, ext = %x\n", n, data, tmpData)
	//if strings.Index(fmt.Sprintf("%v", n), "715ee2cfa181d3e894a577a4d43305ea4a5a6cd809552782d7393d45bd") > 0 {                   //02369dde8dea8ed8ef49cda5449f6f52faaa5def2354bd469dc5770969875aff>" {
	/*
	if strings.Index(fmt.Sprintf("%v", n), "b8281c715ee2cfa181d3e894a5") > 0 {                   //02369dde8dea8ed8ef49cda5449f6f52faaa5def2354bd469dc5770969875aff>" {
		fmt.Printf("here\n")
		debug.PrintStack()
	}
	*/
	//fmt.Printf("~~~~~ hash1= %v, data = %x\n", n, data)
	return n
}













/*
func ethan_find(data []byte) bool {
	var (
		findData = []byte{ 60, 117, 11, 154, 143 } // 030c0705000b090a080f  //3c750b9a8f  //  0x3c, 0x75, 0x0b, 0x9a, 0x8f}  //60, 117, 11, 154, 143 = 3,12,7,5,0,11,9,10,8,15}
	)
	dataLen := len(data)
	findLen := len(findData)

	for i:=0; i < dataLen - findLen; i+=1 {
		j:=0
		for j=0; j < findLen; j+=1 {
			if data[i+j] != findData[j] {
				break
			}
		}
		if j == findLen {
			return true
		}
	}
	return false
}
*/
