package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/wumansgy/goEncrypt"
	"haimian/blockprove/signature"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"time"
)

func main() {
	h := false
	server := flag.String("s", "127.0.0.1:8888", "sever ip and port")
	privateKeyf := flag.String("p", "privatekey", "private key file path")
	flag.BoolVar(&h, "h", false, "this help")
	flag.Parse()
	if h || len(os.Args) <= 1 {
		flag.Usage()
		return
	}

	fmt.Printf("server ip and port: %s\n", *server)
	fmt.Printf("private key file path : %s\n", *privateKeyf)
	fmt.Printf("-------------------------------------------------------\n")

	pb, err := ioutil.ReadFile(*privateKeyf)
	if err != nil {
		fmt.Println("无法读取私有文件")
		panic(err)
	}
	privateKey := string(pb)

	tcpAddr, err := net.ResolveTCPAddr("tcp4", *server)
	checkError(err)
	listener, err := net.ListenTCP("tcp4", tcpAddr)
	checkError(err)
	fmt.Println("时间戳服务器已经开启，等待客户端连接！\n")
	for {
		ts := time.Now().Format("2006-01-02 15:04:05")
		fmt.Println(ts + "等待一个签名请求")
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}
		fmt.Println("客户端链接成功，准备开始接受hash值开始签名。")
		handleClient(conn, privateKey)
		fmt.Println()
	}
}

func handleClient(conn net.Conn, privatekey string) {
	defer conn.Close()
	ut := time.Now().Unix()
	fmt.Println("生成的签名时间为：" + time.Unix(ut, 0).Format("2006-01-02 15:04:05"))
	s := signature.Signature{}
	s.Timestamp = ut
	mbuf := make([]byte, signature.MERKELROOTSIZE)
	_, err := conn.Read(mbuf)
	if err != nil {
		fmt.Println(err)
	}
	s.MerkelRoot = mbuf
	fmt.Println("收到的Markel为：" + hex.EncodeToString(s.MerkelRoot))
	if len(s.MerkelRoot) != signature.MERKELROOTSIZE {
		fmt.Println("读取的Merkel树顶节点长度不是" + strconv.Itoa(signature.MERKELROOTSIZE) + "字节！")
		return
	}
	provemes, err := s.MarshalBinaryProve()
	if err != nil {
		fmt.Println(err)
	}

	rtext, stext, err := goEncrypt.EccSign(provemes, []byte(privatekey))
	s.SetTimeSiganByRS(rtext, stext)
	sn, err := s.MarshalBinary()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(len(s.TimeSignature))
	_, _ = conn.Write(sn)

	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("传送给客户端的签名成功")
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "Fatal error: ", err.Error())
		os.Exit(1)
	}
}
