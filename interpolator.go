package main

import (
	"fmt"
	"github.com/wumansgy/goEncrypt"
	"haimian/blockprove/block"
	"haimian/blockprove/datafactory"
	"haimian/blockprove/signature"
	"io/ioutil"
	"time"
)

func main() {
	blspath2 := "G:\\go_projects\\haimian\\BlockSlice.bin"
	var dfx datafactory.DataFactory = &datafactory.DataFacXls{"C:\\Users\\JC\\Desktop\\data\\xls"}
	pb, err := ioutil.ReadFile("G:\\go_projects\\haimian\\ecc\\publickey")
	if err != nil {
		fmt.Println("无法读取私有文件")
		panic(err)
	}

	privateKey := string(pb)
	bls := block.BlockSlice{}
	bls.TouchOrLoadBlockSlice(blspath2)
	st := "2019-11-21 00:00:00"
	stut, _ := time.Parse("2006-01-02 15:04:05", st)
	stu := stut.Unix()

	for i := 0; i < len(bls); i++ {
		if bls[i].DataStartTime < stu {
			continue
		}

		fmt.Printf("篡改第%d区块\n", i)
		newdhes, _ := dfx.GetDataHashes(bls[i].DataStartTime, bls[i].DataEndTime)
		bls[i].DataHashSlice = &(block.DataHashSlice{})
		for _, v := range newdhes {
			tmp := block.DataHash{}
			tmp.SetValues(v.Key, v.Hvalue)
			bls[i].AddDataHash(&tmp)
		}

		if i > 0 {
			bls[i].PrevBlock = bls[i-1].Hash()
		}

		s := signature.Signature{} //伪造签名
		s.MerkelRoot = bls[i].MerkelRoot
		s.Timestamp = bls[i].SignTimeStamp
		provemes, err := s.MarshalBinaryProve()

		if err != nil {
			fmt.Println(err)
		}

		rtext, stext, err := goEncrypt.EccSign(provemes, []byte(privateKey))
		s.SetTimeSiganByRS(rtext, stext)
		bls[i].TimeSigniture = s.TimeSignature
		bls[i].MerkelRoot = bls[i].GenerateMerkelRoot() //生成新的Merkleroot
		bls[i].Nonce = 1
		bls[i].Nonce = bls[i].GenerateNonce(1) //重新计算Nonce

		fmt.Printf("第%d区块篡改完成\n", i)
	}
	bls.WriteBlockSlice("BlockSlice2.bin")
}
