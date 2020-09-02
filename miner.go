package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/pkg/errors"
	"haimian/blockprove/block"
	"haimian/blockprove/datafactory"
	"haimian/blockprove/signature"
	"net"
	"os"
	"strconv"
	"time"
)

func checkError1(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "Fatal error: ", err.Error())
		os.Exit(1)
	}
}

//从指定服务器，传送merkel获取签名
func getSign(service string, merkel []byte) (signature.Signature, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp4", service)
	checkError1(err)
	conn, err := net.DialTCP("tcp4", nil, tcpAddr)
	defer conn.Close()
	n, err := conn.Write(merkel)
	if n != signature.MERKELROOTSIZE {
		return signature.Signature{}, errors.New("传输的Merkel树顶节点长度不是" + strconv.Itoa(signature.MERKELROOTSIZE) + "字节！")
	}
	if err != nil {
		fmt.Println(err)
		return signature.Signature{}, err
	}
	sbuf := make([]byte, signature.SIGNATURESIZE)
	n, err = conn.Read(sbuf)
	if n != signature.SIGNATURESIZE {
		return signature.Signature{}, errors.New("读取的Merkel树顶节点长度不是" + strconv.Itoa(signature.MERKELROOTSIZE) + "字节！")
	}
	if err != nil {
		fmt.Println(err)
		return signature.Signature{}, err
	}
	var res = signature.Signature{}
	res.UnmarshalBinary(sbuf)
	if bytes.Compare(res.MerkelRoot, merkel) != 0 {
		return signature.Signature{}, errors.New("签名服务器传送过来的Merkel值与初始不一样")
	}
	return res, nil
}

func unixToStr(ut int64) string {
	ut = ut - 8*3600
	return time.Unix(ut, 0).Format("2006-01-02 15:04:05")
}

var (
	h        bool
	server   string
	stimes   string
	etimes   string
	timespan int64
	datapath string
	blspath  string
)

func initargs() {
	flag.StringVar(&server, "s", "127.0.0.1:8888", "Timesever ip and port")
	flag.StringVar(&stimes, "st", "2019-11-20 00:00:00", "Data start time")
	flag.StringVar(&etimes, "et", "2019-11-22 00:00:00", "Data end time")
	flag.Int64Var(&timespan, "i", 1800, "Interval time(s)")
	flag.StringVar(&datapath, "d", "C:\\Users\\JC\\Desktop\\data\\xls", "Data files path")
	flag.StringVar(&blspath, "sp", "BlockSlice.bin", "BlockSlice storage path and filename")
	flag.BoolVar(&h, "h", false, "this help")
	flag.Parse()
}

func showargs() {
	fmt.Printf("timeserver ip and port: %s\n", server)
	fmt.Printf("Data start time : %s\n", stimes)
	fmt.Printf("Data end time : %s\n", etimes)
	fmt.Printf("Data end time : %s\n", etimes)
	fmt.Printf("Data files path : %s\n", datapath)
	fmt.Printf("BlockSlice storage path and filename : %s\n", blspath)
	fmt.Printf("-------------------------------------------------------\n")

}

func main() {
	initargs()
	if h {
		flag.Usage()
		return
	}
	showargs()

	blockslice := block.BlockSlice{}
	blockslice.TouchOrLoadBlockSlice(blspath)

	stime, _ := time.Parse("2006-01-02 15:04:05", stimes)
	etime, _ := time.Parse("2006-01-02 15:04:05", etimes)
	ustime := stime.Unix()
	uetime := etime.Unix()

	var dfx datafactory.DataFactory = &datafactory.DataFacXls{datapath}
	for tmpt := ustime; tmpt+timespan <= uetime; tmpt += timespan {
		fmt.Println("打包" + unixToStr(tmpt) + "到" + unixToStr(tmpt+timespan) + "的数据")
		if len(blockslice) > 0 && blockslice.PreviousBlock().DataEndTime > tmpt {
			fmt.Printf("BlockSlice中已经有%s至%s的数据，跳过此次打包\n", unixToStr(tmpt), unixToStr(blockslice.PreviousBlock().DataEndTime))
			continue
		}
		var prehash []byte
		if len(blockslice) == 0 {
			prehash = []byte("00000000")
		} else {
			prehash = blockslice.PreviousBlock().Hash()
		}
		tmpblock := block.NewBlock(prehash)
		tmpblock.DataStartTime = tmpt
		tmpblock.DataEndTime = tmpt + timespan
		var dhu, err = dfx.GetDataHashes(tmpt, tmpt+timespan)
		if err != nil {
			fmt.Println(err)
			return
		}
		for _, v := range dhu {
			tmpDH := block.DataHash{}
			tmpDH.SetValues(v.Key, v.Hvalue)
			tmpblock.AddDataHash(&tmpDH)
		}

		fmt.Println("该时段区块体打包完成，生成MerkelRoot!")

		tmpblock.MerkelRoot = tmpblock.GenerateMerkelRoot()

		fmt.Printf("将MerkelRoot传送给时间戳服务器签名,其值为%s\n", hex.EncodeToString(tmpblock.MerkelRoot))
		s, err := getSign(server, tmpblock.MerkelRoot)

		if !bytes.Equal(s.MerkelRoot, tmpblock.MerkelRoot) {
			fmt.Println("签名中MerkerRoot不一致，退出程序")
			return
		}
		fmt.Printf("获得签名%s\n", s.TimeSignature)
		tmpblock.TimeSigniture = s.TimeSignature
		tmpblock.SignTimeStamp = s.Timestamp

		fmt.Println("开始寻找一个合适的Nonce值！")
		tmpblock.Nonce = tmpblock.GenerateNonceWithPow(4, "000")
		fmt.Println("该Nonce值为：" + strconv.Itoa(int(tmpblock.Nonce)))

		blockslice = append(blockslice, tmpblock)
		fmt.Println("将该区块存入BlockSlice，并保存到磁盤中")
		err = blockslice.WriteBlockSlice(blspath)

		if err != nil {
			fmt.Println(err)
		}
		fmt.Println("\n")

	}

	fmt.Println("该时间段数据生成私有链完毕")

}
