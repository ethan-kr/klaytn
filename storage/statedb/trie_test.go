// Modifications Copyright 2018 The klaytn Authors
// Copyright 2014 The go-ethereum Authors
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
// This file is derived from trie/trie_test.go (2018/06/04).
// Modified and improved for the klaytn development.

package statedb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"math/big"
	"math/rand"
	"os"
	"reflect"
	"testing"
	"testing/quick"

	"github.com/davecgh/go-spew/spew"
	"github.com/klaytn/klaytn/blockchain/types/account"
	"github.com/klaytn/klaytn/blockchain/types/accountkey"
	"github.com/klaytn/klaytn/common"
	"github.com/klaytn/klaytn/crypto"
	"github.com/klaytn/klaytn/rlp"
	"github.com/klaytn/klaytn/storage/database"
)

func common_HexToHash(s string) common.ExtHash {
	return common.HexToHash(s).ToRootExtHash()
}

func init() {
	spew.Config.Indent = "    "
	spew.Config.DisableMethods = false
}

// Used for testing
func newEmptyTrie() *Trie {
	trie, _ := NewTrie(common.InitExtHash(), NewDatabase(database.NewMemoryDBManager()))
	return trie
}

func TestEmptyTrie(t *testing.T) {
	var trie Trie
	res := trie.Hash()
	exp := emptyRoot
	if res.ToHash() != common.Hash(exp.ToHash()) {
		t.Errorf("expected %x got %x", exp, res)
	}
}

func TestNull(t *testing.T) {
	var trie Trie
	key := make([]byte, 32)
	value := []byte("test")
	trie.Update(key, value)
	if !bytes.Equal(trie.Get(key), value) {
		t.Fatal("wrong value")
	}
}

func TestMissingRoot(t *testing.T) {
	trie, err := NewTrie(common_HexToHash("0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33"), NewDatabase(database.NewMemoryDBManager()))
	if trie != nil {
		t.Error("NewTrie returned non-nil trie for invalid root")
	}
	if _, ok := err.(*MissingNodeError); !ok {
		t.Errorf("NewTrie returned wrong error: %v", err)
	}
}

func TestMissingNodeDisk(t *testing.T)    { testMissingNode(t, false) }
func TestMissingNodeMemonly(t *testing.T) { testMissingNode(t, true) }

func testMissingNode(t *testing.T, memonly bool) {
	memDBManager := database.NewMemoryDBManager()
	diskdb := memDBManager.GetMemDB()
	triedb := NewDatabase(memDBManager)

	trie, _ := NewTrie(common.InitExtHash(), triedb)
	updateString(trie, "120000", "qwerqwerqwerqwerqwerqwerqwerqwer")
	updateString(trie, "123456", "asdfasdfasdfasdfasdfasdfasdfasdf")
	root, _ := trie.Commit(nil, true)
	if !memonly {
		triedb.Commit(root, true, 0)
	}

	trie, _ = NewTrie(root, triedb)
	_, err := trie.TryGet([]byte("120000"))
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	trie, _ = NewTrie(root, triedb)
	_, err = trie.TryGet([]byte("120099"))
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	trie, _ = NewTrie(root, triedb)
	_, err = trie.TryGet([]byte("123456"))
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	trie, _ = NewTrie(root, triedb)
	err = trie.TryUpdate([]byte("120099"), []byte("zxcvzxcvzxcvzxcvzxcvzxcvzxcvzxcv"))
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	trie, _ = NewTrie(root, triedb)
	err = trie.TryDelete([]byte("123456"))
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	hash := common_HexToHash("0xe1d943cc8f061a0c0b98162830b970395ac9315654824bf21b73b891365262f9")
	if memonly {
		delete(triedb.nodes, hash)
	} else {
		diskdb.Delete(hash.ToHash().Bytes())
	}

	trie, _ = NewTrie(root, triedb)
	_, err = trie.TryGet([]byte("120000"))
	if _, ok := err.(*MissingNodeError); !ok {
		t.Errorf("Wrong error: %v", err)
	}
	trie, _ = NewTrie(root, triedb)
	_, err = trie.TryGet([]byte("120099"))
	if _, ok := err.(*MissingNodeError); !ok {
		t.Errorf("Wrong error: %v", err)
	}
	trie, _ = NewTrie(root, triedb)
	_, err = trie.TryGet([]byte("123456"))
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	trie, _ = NewTrie(root, triedb)
	err = trie.TryUpdate([]byte("120099"), []byte("zxcv"))
	if _, ok := err.(*MissingNodeError); !ok {
		t.Errorf("Wrong error: %v", err)
	}
	trie, _ = NewTrie(root, triedb)
	err = trie.TryDelete([]byte("123456"))
	if _, ok := err.(*MissingNodeError); !ok {
		t.Errorf("Wrong error: %v", err)
	}
}

func TestInsert(t *testing.T) {
	trie := newEmptyTrie()

	updateString(trie, "doe", "reindeer")
	updateString(trie, "dog", "puppy")
	updateString(trie, "dogglesworth", "cat")

	exp := common_HexToHash("8aad789dff2f538bca5d8ea56e8abe10f4c7ba3a5dea95fea4cd6e7c3a1168d3")
	root := trie.Hash()
	if root != exp {
		t.Errorf("exp %x got %x", exp, root)
	}

	trie = newEmptyTrie()
	updateString(trie, "A", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	exp = common_HexToHash("d23786fb4a010da3ce639d66d5e904a11dbc02746d1ce25029e53290cabf28ab")
	root, err := trie.Commit(nil, true)
	if err != nil {
		t.Fatalf("commit error: %v", err)
	}
	if root != exp {
		t.Errorf("exp %x got %x", exp, root)
	}
}

func TestGet(t *testing.T) {
	trie := newEmptyTrie()
	updateString(trie, "doe", "reindeer")
	updateString(trie, "dog", "puppy")
	updateString(trie, "dogglesworth", "cat")

	for i := 0; i < 2; i++ {
		res := getString(trie, "dog")
		if !bytes.Equal(res, []byte("puppy")) {
			t.Errorf("expected puppy got %x", res)
		}

		unknown := getString(trie, "unknown")
		if unknown != nil {
			t.Errorf("expected nil got %x", unknown)
		}

		if i == 1 {
			return
		}
		trie.Commit(nil, true)
	}
}

func TestDelete(t *testing.T) {
	trie := newEmptyTrie()
	vals := []struct{ k, v string }{
		{"do", "verb"},
		{"klaytn", "wookiedoo"},
		{"horse", "stallion"},
		{"shaman", "horse"},
		{"doge", "coin"},
		{"klaytn", ""},
		{"dog", "puppy"},
		{"shaman", ""},
	}
	for _, val := range vals {
		if val.v != "" {
			updateString(trie, val.k, val.v)
		} else {
			deleteString(trie, val.k)
		}
	}

	hash := trie.Hash()
	exp := common_HexToHash("5991bb8c6514148a29db676a14ac506cd2cd5775ace63c30a4fe457715e9ac84")
	if hash != exp {
		t.Errorf("expected %x got %x", exp, hash)
	}
}

func TestEmptyValues(t *testing.T) {
	trie := newEmptyTrie()

	vals := []struct{ k, v string }{
		{"do", "verb"},
		{"klaytn", "wookiedoo"},
		{"horse", "stallion"},
		{"shaman", "horse"},
		{"doge", "coin"},
		{"klaytn", ""},
		{"dog", "puppy"},
		{"shaman", ""},
	}
	for _, val := range vals {
		updateString(trie, val.k, val.v)
	}

	hash := trie.Hash()
	exp := common_HexToHash("5991bb8c6514148a29db676a14ac506cd2cd5775ace63c30a4fe457715e9ac84")
	if hash != exp {
		t.Errorf("expected %x got %x", exp, hash)
	}
}

func TestReplication(t *testing.T) {
	trie := newEmptyTrie()
	vals := []struct{ k, v string }{
		{"do", "verb"},
		{"klaytn", "wookiedoo"},
		{"horse", "stallion"},
		{"shaman", "horse"},
		{"doge", "coin"},
		{"dog", "puppy"},
		{"somethingveryoddindeedthis is", "myothernodedata"},
	}
	for _, val := range vals {
		updateString(trie, val.k, val.v)
	}
	exp, err := trie.Commit(nil, true)
	if err != nil {
		t.Fatalf("commit error: %v", err)
	}

	// create a new trie on top of the database and check that lookups work.
	trie2, err := NewTrie(exp, trie.db)
	if err != nil {
		t.Fatalf("can't recreate trie at %x: %v", exp, err)
	}
	for _, kv := range vals {
		if string(getString(trie2, kv.k)) != kv.v {
			t.Errorf("trie2 doesn't have %q => %q", kv.k, kv.v)
		}
	}
	hash, err := trie2.Commit(nil, true)
	if err != nil {
		t.Fatalf("commit error: %v", err)
	}
	if hash != exp {
		t.Errorf("root failure. expected %x got %x", exp, hash)
	}

	// perform some insertions on the new trie.
	vals2 := []struct{ k, v string }{
		{"do", "verb"},
		{"klaytn", "wookiedoo"},
		{"horse", "stallion"},
		// {"shaman", "horse"},
		// {"doge", "coin"},
		// {"klaytn", ""},
		// {"dog", "puppy"},
		// {"somethingveryoddindeedthis is", "myothernodedata"},
		// {"shaman", ""},
	}
	for _, val := range vals2 {
		updateString(trie2, val.k, val.v)
	}
	if hash := trie2.Hash(); hash != exp {
		t.Errorf("root failure. expected %x got %x", exp, hash)
	}
}

func TestLargeValue(t *testing.T) {
	trie := newEmptyTrie()
	trie.Update([]byte("key1"), []byte{99, 99, 99, 99})
	trie.Update([]byte("key2"), bytes.Repeat([]byte{1}, 32))
	trie.Hash()
}

type countingDB struct {
	database.DBManager
	gets map[string]int
}

//func (db *countingDB) Get(key []byte) ([]byte, error) {
//	db.gets[string(key)]++
//	return db.Database.Get(key)
//}

// randTest performs random trie operations.
// Instances of this test are created by Generate.
type randTest []randTestStep

type randTestStep struct {
	op    int
	key   []byte // for opUpdate, opDelete, opGet
	value []byte // for opUpdate
	err   error  // for debugging
}

const (
	opUpdate = iota
	opDelete
	opGet
	opCommit
	opHash
	opReset
	opItercheckhash
	opMax // boundary value, not an actual op
)

func (randTest) Generate(r *rand.Rand, size int) reflect.Value {
	var allKeys [][]byte
	genKey := func() []byte {
		if len(allKeys) < 2 || r.Intn(100) < 10 {
			// new key
			key := make([]byte, r.Intn(50))
			r.Read(key)
			allKeys = append(allKeys, key)
			return key
		}
		// use existing key
		return allKeys[r.Intn(len(allKeys))]
	}

	var steps randTest
	for i := 0; i < size; i++ {
		step := randTestStep{op: r.Intn(opMax)}
		switch step.op {
		case opUpdate:
			step.key = genKey()
			step.value = make([]byte, 8)
			binary.BigEndian.PutUint64(step.value, uint64(i))
		case opGet, opDelete:
			step.key = genKey()
		}
		steps = append(steps, step)
	}
	return reflect.ValueOf(steps)
}

func runRandTest(rt randTest) bool {
	triedb := NewDatabase(database.NewMemoryDBManager())

	tr, _ := NewTrie(common.InitExtHash(), triedb)
	values := make(map[string]string) // tracks content of the trie

	for i, step := range rt {
		switch step.op {
		case opUpdate:
			tr.Update(step.key, step.value)
			values[string(step.key)] = string(step.value)
		case opDelete:
			tr.Delete(step.key)
			delete(values, string(step.key))
		case opGet:
			v := tr.Get(step.key)
			want := values[string(step.key)]
			if string(v) != want {
				rt[i].err = fmt.Errorf("mismatch for key 0x%x, got 0x%x want 0x%x", step.key, v, want)
			}
		case opCommit:
			_, rt[i].err = tr.Commit(nil, true)
		case opHash:
			tr.Hash()
		case opReset:
			hash, err := tr.Commit(nil, true)
			if err != nil {
				rt[i].err = err
				return false
			}
			newtr, err := NewTrie(hash, triedb)
			if err != nil {
				rt[i].err = err
				return false
			}
			tr = newtr
		case opItercheckhash:
			checktr, _ := NewTrie(common.InitExtHash(), triedb)
			it := NewIterator(tr.NodeIterator(nil))
			for it.Next() {
				checktr.Update(it.Key, it.Value)
			}
			if tr.Hash() != checktr.Hash() {
				rt[i].err = fmt.Errorf("hash mismatch in opItercheckhash")
			}
		}
		// Abort the test on error.
		if rt[i].err != nil {
			return false
		}
	}
	return true
}

func TestRandom(t *testing.T) {
	if err := quick.Check(runRandTest, nil); err != nil {
		if cerr, ok := err.(*quick.CheckError); ok {
			t.Fatalf("random test iteration %d failed: %s", cerr.Count, spew.Sdump(cerr.In))
		}
		t.Fatal(err)
	}
}

func BenchmarkGet(b *testing.B)      { benchGet(b, false) }
func BenchmarkGetDB(b *testing.B)    { benchGet(b, true) }
func BenchmarkUpdateBE(b *testing.B) { benchUpdate(b, binary.BigEndian) }
func BenchmarkUpdateLE(b *testing.B) { benchUpdate(b, binary.LittleEndian) }

const benchElemCount = 20000

func benchGet(b *testing.B, commit bool) {
	trie := new(Trie)

	if commit {
		dbDir, tmpdb := tempDB()
		trie, _ = NewTrie(common.InitExtHash(), tmpdb)

		defer os.RemoveAll(dbDir)
		defer tmpdb.diskDB.Close()
	}

	k := make([]byte, 32)
	for i := 0; i < benchElemCount; i++ {
		binary.LittleEndian.PutUint64(k, uint64(i))
		trie.Update(k, k)
	}
	binary.LittleEndian.PutUint64(k, benchElemCount/2)
	if commit {
		trie.Commit(nil, true)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		trie.Get(k)
	}
	b.StopTimer()
}

func benchUpdate(b *testing.B, e binary.ByteOrder) *Trie {
	trie := newEmptyTrie()
	k := make([]byte, 32)
	for i := 0; i < b.N; i++ {
		e.PutUint64(k, uint64(i))
		trie.Update(k, k)
	}
	return trie
}

// Benchmarks the trie hashing. Since the trie caches the result of any operation,
// we cannot use b.N as the number of hashing rouns, since all rounds apart from
// the first one will be NOOP. As such, we'll use b.N as the number of account to
// insert into the trie before measuring the hashing.
func BenchmarkHash(b *testing.B) {
	// Make the random benchmark deterministic
	random := rand.New(rand.NewSource(0))

	// Create a realistic account trie to hash
	addresses := make([][20]byte, b.N)
	for i := 0; i < len(addresses); i++ {
		for j := 0; j < len(addresses[i]); j++ {
			addresses[i][j] = byte(random.Intn(256))
		}
	}
	accounts := make([][]byte, len(addresses))
	for i := 0; i < len(accounts); i++ {
		var (
			nonce   = uint64(random.Int63())
			balance = new(big.Int).Rand(random, new(big.Int).Exp(common.Big2, common.Big256, nil))
			root    = emptyRoot
			code    = crypto.Keccak256(nil)
		)
		accounts[i], _ = rlp.EncodeToBytes([]interface{}{nonce, balance, root, code})
	}
	// Insert the accounts into the trie and hash it
	trie := newEmptyTrie()
	for i := 0; i < len(addresses); i++ {
		trie.Update(crypto.Keccak256(addresses[i][:]), accounts[i])
	}
	b.ResetTimer()
	b.ReportAllocs()
	trie.Hash()
}

// Benchmarks the trie Commit following a Hash. Since the trie caches the result of any operation,
// we cannot use b.N as the number of hashing rounds, since all rounds apart from
// the first one will be NOOP. As such, we'll use b.N as the number of account to
// insert into the trie before measuring the hashing.
func BenchmarkCommitAfterHash(b *testing.B) {
	b.Run("no-onleaf", func(b *testing.B) {
		benchmarkCommitAfterHash(b)
	})
}

func benchmarkCommitAfterHash(b *testing.B) {
	// Make the random benchmark deterministic
	addresses, accounts := makeAccounts(b.N)
	trie, _ := NewTrie(common.InitExtHash(), NewDatabase(database.NewMemoryDBManager()))
	for i := 0; i < len(addresses); i++ {
		trie.Update(crypto.Keccak256(addresses[i][:]), accounts[i])
	}
	// Insert the accounts into the trie and hash it
	trie.Hash()
	b.ResetTimer()
	b.ReportAllocs()
	trie.Commit(nil, true)
}

func tempDB() (string, *Database) {
	dir, err := ioutil.TempDir("", "trie-bench")
	if err != nil {
		panic(fmt.Sprintf("can't create temporary directory: %v", err))
	}
	dbc := &database.DBConfig{Dir: dir, DBType: database.LevelDB, LevelDBCacheSize: 256, OpenFilesLimit: 0}
	diskDB := database.NewDBManager(dbc)
	return dir, NewDatabase(diskDB)
}

func genExternallyOwnedAccount(nonce uint64, balance *big.Int) (account.Account, error) {
	return account.NewAccountWithMap(account.ExternallyOwnedAccountType, map[account.AccountValueKeyType]interface{}{
		account.AccountValueKeyNonce:         nonce,
		account.AccountValueKeyBalance:       balance,
		account.AccountValueKeyHumanReadable: false,
		account.AccountValueKeyAccountKey:    accountkey.NewAccountKeyLegacy(),
	})
}

func makeAccounts(size int) (addresses [][20]byte, accounts [][]byte) {
	// Make the random benchmark deterministic
	random := rand.New(rand.NewSource(0))
	// Create a realistic account trie to hash
	addresses = make([][20]byte, size)
	for i := 0; i < len(addresses); i++ {
		data := make([]byte, 20)
		random.Read(data)
		copy(addresses[i][:], data)
	}
	accounts = make([][]byte, len(addresses))
	for i := 0; i < len(accounts); i++ {
		// The big.Rand function is not deterministic with regards to 64 vs 32 bit systems,
		// and will consume different amount of data from the rand source.
		// balance = new(big.Int).Rand(random, new(big.Int).Exp(common.Big2, common.Big256, nil))
		// Therefore, we instead just read via byte buffer
		numBytes := random.Uint32() % 33 // [0, 32] bytes
		balanceBytes := make([]byte, numBytes)
		random.Read(balanceBytes)
		acc, _ := genExternallyOwnedAccount(uint64(i), big.NewInt(int64(i)))
		serializer := account.NewAccountSerializerWithAccount(acc)
		data, _ := rlp.EncodeToBytes(serializer)
		accounts[i] = data
	}
	return addresses, accounts
}

// BenchmarkCommitAfterHashFixedSize benchmarks the Commit (after Hash) of a fixed number of updates to a trie.
// This benchmark is meant to capture the difference on efficiency of small versus large changes. Typically,
// storage tries are small (a couple of entries), whereas the full post-block account trie update is large (a couple
// of thousand entries)
func BenchmarkHashFixedSize(b *testing.B) {
	b.Run("10", func(b *testing.B) {
		b.StopTimer()
		acc, add := makeAccounts(20)
		for i := 0; i < b.N; i++ {
			benchmarkHashFixedSize(b, acc, add)
		}
	})
	b.Run("100", func(b *testing.B) {
		b.StopTimer()
		acc, add := makeAccounts(100)
		for i := 0; i < b.N; i++ {
			benchmarkHashFixedSize(b, acc, add)
		}
	})

	b.Run("1K", func(b *testing.B) {
		b.StopTimer()
		acc, add := makeAccounts(1000)
		for i := 0; i < b.N; i++ {
			benchmarkHashFixedSize(b, acc, add)
		}
	})
	b.Run("10K", func(b *testing.B) {
		b.StopTimer()
		acc, add := makeAccounts(10000)
		for i := 0; i < b.N; i++ {
			benchmarkHashFixedSize(b, acc, add)
		}
	})
	b.Run("100K", func(b *testing.B) {
		b.StopTimer()
		acc, add := makeAccounts(100000)
		for i := 0; i < b.N; i++ {
			benchmarkHashFixedSize(b, acc, add)
		}
	})
}

func benchmarkHashFixedSize(b *testing.B, addresses [][20]byte, accounts [][]byte) {
	b.ReportAllocs()
	trie, _ := NewTrie(common.InitExtHash(), NewDatabase(database.NewMemoryDBManager()))
	for i := 0; i < len(addresses); i++ {
		trie.Update(crypto.Keccak256(addresses[i][:]), accounts[i])
	}
	// Insert the accounts into the trie and hash it
	b.StartTimer()
	trie.Hash()
	b.StopTimer()
}

func BenchmarkCommitAfterHashFixedSize(b *testing.B) {
	b.Run("10", func(b *testing.B) {
		b.StopTimer()
		acc, add := makeAccounts(20)
		for i := 0; i < b.N; i++ {
			benchmarkCommitAfterHashFixedSize(b, acc, add)
		}
	})
	b.Run("100", func(b *testing.B) {
		b.StopTimer()
		acc, add := makeAccounts(100)
		for i := 0; i < b.N; i++ {
			benchmarkCommitAfterHashFixedSize(b, acc, add)
		}
	})

	b.Run("1K", func(b *testing.B) {
		b.StopTimer()
		acc, add := makeAccounts(1000)
		for i := 0; i < b.N; i++ {
			benchmarkCommitAfterHashFixedSize(b, acc, add)
		}
	})
	b.Run("10K", func(b *testing.B) {
		b.StopTimer()
		acc, add := makeAccounts(10000)
		for i := 0; i < b.N; i++ {
			benchmarkCommitAfterHashFixedSize(b, acc, add)
		}
	})
	b.Run("100K", func(b *testing.B) {
		b.StopTimer()
		acc, add := makeAccounts(100000)
		for i := 0; i < b.N; i++ {
			benchmarkCommitAfterHashFixedSize(b, acc, add)
		}
	})
}

func benchmarkCommitAfterHashFixedSize(b *testing.B, addresses [][20]byte, accounts [][]byte) {
	b.ReportAllocs()
	trie, _ := NewTrie(common.InitExtHash(), NewDatabase(database.NewMemoryDBManager()))
	for i := 0; i < len(addresses); i++ {
		trie.Update(crypto.Keccak256(addresses[i][:]), accounts[i])
	}
	// Insert the accounts into the trie and hash it
	trie.Hash()
	b.StartTimer()
	trie.Commit(nil, true)
	b.StopTimer()
}

func BenchmarkDerefRootFixedSize(b *testing.B) {
	b.Run("10", func(b *testing.B) {
		b.StopTimer()
		acc, add := makeAccounts(20)
		for i := 0; i < b.N; i++ {
			benchmarkDerefRootFixedSize(b, acc, add)
		}
	})
	b.Run("100", func(b *testing.B) {
		b.StopTimer()
		acc, add := makeAccounts(100)
		for i := 0; i < b.N; i++ {
			benchmarkDerefRootFixedSize(b, acc, add)
		}
	})

	b.Run("1K", func(b *testing.B) {
		b.StopTimer()
		acc, add := makeAccounts(1000)
		for i := 0; i < b.N; i++ {
			benchmarkDerefRootFixedSize(b, acc, add)
		}
	})
	b.Run("10K", func(b *testing.B) {
		b.StopTimer()
		acc, add := makeAccounts(10000)
		for i := 0; i < b.N; i++ {
			benchmarkDerefRootFixedSize(b, acc, add)
		}
	})
	b.Run("100K", func(b *testing.B) {
		b.StopTimer()
		acc, add := makeAccounts(100000)
		for i := 0; i < b.N; i++ {
			benchmarkDerefRootFixedSize(b, acc, add)
		}
	})
}

func benchmarkDerefRootFixedSize(b *testing.B, addresses [][20]byte, accounts [][]byte) {
	b.ReportAllocs()
	triedb := NewDatabase(database.NewMemoryDBManager())
	trie, _ := NewTrie(common.InitExtHash(), triedb)
	for i := 0; i < len(addresses); i++ {
		trie.Update(crypto.Keccak256(addresses[i][:]), accounts[i])
	}
	h := trie.Hash()
	trie.Commit(nil, true)
	//_, nodes := trie.Commit(nil, true)
	//triedb.Update(NewWithNodeSet(nodes))
	b.StartTimer()
	triedb.Dereference(h)
	b.StopTimer()
}

func getString(trie *Trie, k string) []byte {
	return trie.Get([]byte(k))
}

func updateString(trie *Trie, k, v string) {
	trie.Update([]byte(k), []byte(v))
}

func deleteString(trie *Trie, k string) {
	trie.Delete([]byte(k))
}

func TestDecodeNode(t *testing.T) {
	t.Parallel()
	var (
		hash  = make([]byte, 20)
		elems = make([]byte, 20)
	)
	for i := 0; i < 5000000; i++ {
		rand.Read(hash)
		rand.Read(elems)
		decodeNode(hash, elems)
	}
}
