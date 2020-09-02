package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/AidosKuneen/cuckoo"
	"github.com/wumansgy/goEncrypt"
	"haimian/blockprove/block"
	"haimian/blockprove/datafactory"
	"haimian/blockprove/signature"
	"io/ioutil"
	"time"
)



func validateSign(sn signature.Signature, publickey string) bool{
	msg, err := sn.MarshalBinaryProve()
	if err!= nil {
		fmt.Println(err)
	}
	rtext, stext := sn.GetRS()
	return goEncrypt.EccVerifySign(msg, []byte(publickey), rtext, stext)
}

func unixToStr2(ut int64) string{
	ut = ut - 8*3600
	return time.Unix(ut, 0).Format("2006-01-02 15:04:05")
}

func readpubkey(p string) string{
	k, err := ioutil.ReadFile(p)
	if err != nil {
		fmt.Println("公钥读取错误")
		panic(err)
	}
	return string(k)
}

var(
	h2 bool
	publicKeyf string
//	stimes string
//	etimes string
	datapath2 string
	blspath2 string
)

func initargs2() {
	flag.StringVar(&publicKeyf,"p","G:\\go_projects\\haimian\\ecc\\publicKey", "publickey file path")
	flag.StringVar(&datapath2 ,"d","C:\\Users\\JC\\Desktop\\data\\xls","Data files path")
	flag.StringVar(&blspath2 ,"sp","G:\\go_projects\\haimian\\BlockSlice.bin","BlockSlice storage path and filename")
	flag.BoolVar(&h2, "h", false, "this help")
	flag.Parse()
}

func showargs2(){
	fmt.Printf("publicKey: %s\n", publicKeyf)
	fmt.Printf("Data files path : %s\n", datapath2)
	fmt.Printf("BlockSlice storage path and filename : %s\n", blspath2)
	fmt.Printf("-------------------------------------------------------\n")

}



func main(){
	initargs2()
	if h2 {
		flag.Usage()
		return
	}
	showargs2()
	publicKey := readpubkey(publicKeyf)
	bls := block.BlockSlice{}
	bls.TouchOrLoadBlockSlice(blspath2)
	var  dfx datafactory.DataFactory = &datafactory.DataFacXls{datapath2}
	for i, v := range bls{
		if i != 0{
			if !bytes.Equal(v.BlockHeader.PrevBlock, bls[i-1].Hash()){
				fmt.Printf("区块%d无法链接上一区块\n",i)
			}
		}
		st := v.DataStartTime
		et := v.DataEndTime
		fmt.Printf("验证第%d个区块%s到%s的数据\n", i, unixToStr2(st), unixToStr2(et))
		dhs, err := dfx.GetDataHashes(st, et)
		if err != nil{
			panic(err)
		}
		tmpdhslice := v.GetDataHashSlice()

		if len(tmpdhslice) != len(dhs) {
			fmt.Println("该时段传感器数据不全！")
			continue
		}
		ok := true
		for j := 0;j < len(dhs);j++ {
			_, th := tmpdhslice[j].GetValues()
			if !bytes.Equal(th, dhs[j].Hvalue){
				fmt.Printf("编号%s的数据Hash值不匹配\n",dhs[j].Name)
				ok = false
			}
		}
		if ok{
			fmt.Println("所有哈希值匹配")
			s := signature.Signature{}
			s.TimeSignature = v.TimeSigniture
			s.MerkelRoot = v.MerkelRoot
			s.Timestamp = v.SignTimeStamp
			if  validateSign(s, publicKey) {
				fmt.Printf("区块%d时间签名正确\n", i)
			}

			if (v.SignTimeStamp - v.DataEndTime) > 3 * (v.DataEndTime - v.DataStartTime) {
				fmt.Printf("签名时间%s比数据结尾时间%s过大，属于历史数据签名，数据实时性无效。\n", unixToStr2(v.SignTimeStamp), unixToStr2(v.DataEndTime))
			}else {
				fmt.Printf("该区块属于实时签名\n")
			}

			cu := cuckoo.NewCuckoo(1)
			_, found := cu.PoW(v.Hash())
			if found {
				fmt.Println("该区块工作量有效")
			}else {
				fmt.Printf("该区块工作量无效")
			}
		}
		fmt.Println("")
	}
}