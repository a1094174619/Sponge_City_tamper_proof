package block

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/AidosKuneen/cuckoo"
	"github.com/izqui/functional"
	"github.com/izqui/helpers"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Block struct {
	*BlockHeader
	*DataHashSlice
}

func (b *Block) VerifyBlock() bool {
	return true
}

func (b *Block) GetDataHashSlice() DataHashSlice {
	return *(b.DataHashSlice)
}

func (b *Block) AddDataHash(d *DataHash) {
	newSlice := b.DataHashSlice.AddDataHash(*d)
	b.DataHashSlice = &newSlice
}

func (b *Block) Hash() []byte {

	headerHash, _ := b.BlockHeader.MarshalBinary()
	return helpers.SHA256(headerHash)
}

func (b *Block) MarshalBinary() ([]byte, error) {

	bhb, err := b.BlockHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	//sig := helpers.FitBytesInto(b.Signature, NETWORK_KEY_SIZE)
	tsb, err := b.DataHashSlice.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return append(bhb, tsb...), nil
}

func (b *Block) UnmarshalBinary(d []byte) error {

	buf := bytes.NewBuffer(d)

	header := new(BlockHeader)
	err := header.UnmarshalBinary(buf.Next(BLOCKHEADSIZE))
	if err != nil {
		return err
	}

	b.BlockHeader = header

	ts := new(DataHashSlice)
	err = ts.UnmarshalBinary(buf.Next(helpers.MaxInt))
	if err != nil {
		return err
	}

	b.DataHashSlice = ts

	return nil
}

//func (b *Block) MarshalBinary() ([]byte, error) {
//
//}
func (b *Block) GenerateMerkelRoot() []byte {

	var merkell func(hashes [][]byte) []byte
	merkell = func(hashes [][]byte) []byte {

		l := len(hashes)
		if l == 0 {
			return nil
		}
		if l == 1 {
			return hashes[0]
		} else {

			if l%2 == 1 {
				return merkell([][]byte{merkell(hashes[:l-1]), hashes[l-1]})
			}

			bs := make([][]byte, l/2)
			for i, _ := range bs {
				j, k := i*2, (i*2)+1
				bs[i] = helpers.SHA256(append(hashes[j], hashes[k]...))
			}
			return merkell(bs)
		}
	}

	ts := functional.Map(func(d DataHash) []byte { return d.Hash() }, []DataHash(*b.DataHashSlice)).([][]byte)
	return merkell(ts)

}

func (b *Block) GenerateNonce(concurrentNum int) uint32 {
	st := time.Now().Unix()
	newB := b
	cu := cuckoo.NewCuckoo(8)
	os.Stdout.Sync()
	for {
		solutionnonces, found := cu.PoW(newB.Hash())
		if !found {
			newB.BlockHeader.Nonce++
			fmt.Printf("\r正在计算的Nonce值为：%d", newB.BlockHeader.Nonce)
		} else {
			fmt.Println()
			err := cuckoo.Verify(newB.Hash(), solutionnonces)
			if err != nil {
				fmt.Println(err)
				newB.BlockHeader.Nonce++
				//failed to verify
			} else {
				fmt.Printf("找到Nonce值")
				break
			}
		}
	}
	et := time.Now().Unix()
	us := et - st
	fmt.Println("生成区块头用时：" + strconv.Itoa(int(us/60)) + "分" + strconv.Itoa(int(us%60)) + "秒")
	return newB.BlockHeader.Nonce
}

func (b *Block) GenerateNonceWithPow(concurrentNum int, prefix string) uint32 {
	st := time.Now().Unix()
	os.Stdout.Sync()
	var wg sync.WaitGroup
	wg.Add(concurrentNum)
	var resNonce uint32 = 0

	cal := func(k int) {
		defer wg.Done()

		tmpB := &Block{
			BlockHeader: &BlockHeader{
				PrevBlock:     b.PrevBlock,
				SignTimeStamp: b.SignTimeStamp,
				TimeSigniture: b.TimeSigniture,
				DataStartTime: b.DataStartTime,
				DataEndTime:   b.DataEndTime,
				MerkelRoot:    b.MerkelRoot,
				Nonce:         0,
			},
			DataHashSlice: b.DataHashSlice,
		}

		for i := 0; ; i++ {
			if atomic.LoadUint32(&resNonce) != uint32(0) {
				return
			}

			base := i * 10000 * concurrentNum
			for j := 1; j < 10000; j++ {
				tmpB.BlockHeader.Nonce = uint32(base + j)
				tmpHash := tmpB.Hash()
				if !strings.HasPrefix(string(tmpHash), prefix) {
					fmt.Printf("\r正在计算的Nonce值为：%d", tmpB.BlockHeader.Nonce)
				} else {
					fmt.Println("找到Nonce值")
					atomic.StoreUint32(&resNonce, tmpB.BlockHeader.Nonce)
					return
				}
			}
		}
	}

	for i := 0; i < concurrentNum; i++ {
		go cal(i)
	}

	wg.Wait()
	et := time.Now().Unix()
	us := et - st
	fmt.Println("生成区块头用时：" + strconv.Itoa(int(us/60)) + "分" + strconv.Itoa(int(us%60)) + "秒")
	return resNonce
}

type BlockHeader struct {
	PrevBlock []byte //上一个块hash
	//Solutions [20]uint32 //解决方案nonces
	SignTimeStamp int64 //Unix时间戳
	TimeSigniture []byte
	DataStartTime int64
	DataEndTime   int64
	MerkelRoot    []byte
	Nonce         uint32
}

func (h *BlockHeader) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.Write(helpers.FitBytesInto(h.PrevBlock, PREBLOCKHASH))
	binary.Write(buf, binary.LittleEndian, h.SignTimeStamp)
	buf.Write(helpers.FitBytesInto(h.TimeSigniture, TIMESIGNITURE))
	binary.Write(buf, binary.LittleEndian, h.DataStartTime)
	binary.Write(buf, binary.LittleEndian, h.DataEndTime)
	buf.Write(helpers.FitBytesInto(h.MerkelRoot, MARKELROOT))
	binary.Write(buf, binary.LittleEndian, h.Nonce)
	return buf.Bytes(), nil
}

func (h *BlockHeader) UnmarshalBinary(d []byte) error {
	buf := bytes.NewBuffer(d)
	h.PrevBlock = buf.Next(PREBLOCKHASH)
	binary.Read(bytes.NewBuffer(buf.Next(SIGNTIMESTAMP)), binary.LittleEndian, &h.SignTimeStamp)
	h.TimeSigniture = buf.Next(TIMESIGNITURE)
	binary.Read(bytes.NewBuffer(buf.Next(SIGNTIMESTAMP)), binary.LittleEndian, &h.DataStartTime)
	binary.Read(bytes.NewBuffer(buf.Next(SIGNTIMESTAMP)), binary.LittleEndian, &h.DataEndTime)
	h.MerkelRoot = buf.Next(MARKELROOT)
	binary.Read(bytes.NewBuffer(buf.Next(NONCE)), binary.LittleEndian, &h.Nonce)
	return nil
}

type BlockSlice []Block

func (bs BlockSlice) PreviousBlock() *Block {
	l := len(bs)
	if l == 0 {
		return nil
	} else {
		return &bs[l-1]
	}
}

func (bs *BlockSlice) MarshalBinary() ([]byte, error) {
	sep := []byte(BLOCKSLICEINTERVAL)
	buf := new(bytes.Buffer)
	for i, v := range *bs {
		tmp, err := v.MarshalBinary()
		if err != nil {
			return nil, err
		}
		buf.Write(tmp)
		if i != len(*bs)-1 {
			buf.Write(sep)
		}
	}
	return buf.Bytes(), nil
}

func (bs *BlockSlice) UnmarshalBinary(d []byte) error {
	sep := []byte(BLOCKSLICEINTERVAL)
	var barr = bytes.Split(d, sep)
	for _, v := range barr {
		tmpBlock := new(Block)
		tmpBlock.UnmarshalBinary(v)
		*bs = append(*bs, *tmpBlock)
	}
	return nil
}

func (s *BlockSlice) AppendBlockToFile(fpath string) {
	// If the file doesn't exist, create it, or append to the file
	f, err := os.OpenFile(fpath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	if len(*s) > 0 {
		_, err = f.Write([]byte(BLOCKSLICEINTERVAL))
		if err != nil {
			panic(err)
		}
	}
	pb, _ := s.PreviousBlock().MarshalBinary()
	_, err = f.Write([]byte(pb))
	if err != nil {
		panic(err)
	}
}

func (s *BlockSlice) WriteBlockSlice(fpath string) error {
	b, err := s.MarshalBinary()
	fmt.Printf("写入BlockSlice的长度是%d字节\n", len(b))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(fpath, b, 0644)
	if err != nil {
		return nil
	}
	return nil
}

func (s *BlockSlice) TouchOrLoadBlockSlice(fpath string) {
	isExist := func(filename string) bool {
		_, err := os.Stat(filename)
		return err == nil || os.IsExist(err)
	}
	if isExist(fpath) {
		b, err := ioutil.ReadFile(fpath)
		if err != nil {
			fmt.Println(err)
		}
		s.UnmarshalBinary(b)
	}
}

func NewBlock(previousBlock []byte) Block {
	header := &BlockHeader{PrevBlock: previousBlock}
	return Block{header, new(DataHashSlice)}
}
