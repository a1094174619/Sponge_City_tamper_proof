package datafactory

import (
	"bytes"
	//"github.com/pkg/errors"
	"strings"
	//"flag"
	"fmt"
	"github.com/360EntSecGroup-Skylar/excelize"
	"github.com/izqui/helpers"
	"os"
	"path/filepath"
	"strconv"
	"time"
)


var (
	keyname = make(map[string]uint32)
	keymax uint32 = 0
	ostype = os.Getenv("GOOS") // 获取系统类型
	itoa = []string{"A", "B", "C", "D", "E" , "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X" ,"Y", "Z"}
)

var listfile []string //获取文件列表

func listfunc(path string, f os.FileInfo, err error) error {
	var strRet string
	//strRet, _ = os.Getwd()
	//ostype := os.Getenv("GOOS") // windows, linux
	if ostype == "windows" {
		strRet += "\\"
	} else if ostype == "linux" {
		strRet += "/"
	}
	if f == nil {
		return err
	}
	if f.IsDir() {
		return nil
	}
	strRet += path //+ "\r\n"
	 //用strings.HasSuffix(src, suffix)//判断src中是否包含 suffix结尾
	//ok := strings.HasSuffix(strRet, ".go")
	//if ok {
	listfile = append(listfile, strRet) //将目录push到listfile []string中 // }
	//}
	     //fmt.Println(ostype) // print ostype
	//fmt.Println(strRet) //list the file
	return nil
}

func getFileList(path string) []string {
	//var strRet string
	listfile = listfile[:0]
	err := filepath.Walk(path, listfunc)
	if err != nil {
		fmt.Printf("filepath.Walk() returned %v\n", err)
	}
	return listfile
}

func compareTimeUinx(ustime int64, uetime int64, untime  int64) int {
	if untime < ustime {
		return -1
	}else if untime >= ustime && untime < uetime {
		return 0
	}else {
		return 1
	}
}


type DataFactory interface {
	GetData(stime int64, endtime int64) ([]DataUnit, error)
	GetDataHashes(stime int64, etime int64) ([]DataHashUnit, error)
}

type DataUnit struct {
	Key uint32
	Name string
	Value []byte
}
func (du *DataUnit) Hash() []byte{
	return helpers.SHA256(du.Value)
}

type DataHashUnit struct {
	Key uint32
	Name string
	Hvalue []byte
}



type DataFacXls struct {
	Fname string
}

func (dfx *DataFacXls) GetData(stime int64, endtime int64) ([]DataUnit, error) {
	var files = getFileList(dfx.Fname)
	var res []DataUnit
	for _, fn := range files {
		if !(strings.Contains(fn, "xls") || strings.Contains(fn, "xlsx")){
			fmt.Printf("文件%s不是excel文件，跳过", fn)
			continue
		}
		tmpdu := DataUnit{}
		f, err := excelize.OpenFile(fn)
		if err != nil {
			fmt.Println(fn + "读取错误！")
			panic(err)
			continue
		}
		sheetname := f.GetSheetName(1)

		fc,_ := f.GetCellValue(sheetname,"A2")//编号
		if fc == ""{//没有数据终止读取
			continue
		}else {
			if v, ok := keyname[fc]; ok{
				tmpdu.Name = fc
				tmpdu.Key = v
			}else {
				tmpdu.Name = fc
				keyname[fc] = keymax
				tmpdu.Key = keymax
				keymax ++
			}
		}
		fmt.Printf("\r打包序号为%s,编号为%s的数据", strconv.Itoa(int(tmpdu.Key)), tmpdu.Name)
		colnum := 0//获取列数
		for {
			cv, err:= f.GetCellValue(sheetname, itoa[colnum] + "1")
			if err != nil {
				return nil, err
			}
			if cv != "" {
				colnum++
			}else {
				break
			}
		}
		buf := new(bytes.Buffer)
		buf.Reset()
		for i := 2;true ; i++ {
			fc,_ := f.GetCellValue(sheetname,"A" + strconv.Itoa(i))
			if fc == ""{//没有数据终止读取
				break
			}
			tcs,_ := f.GetCellValue(sheetname,"B" + strconv.Itoa(i))
			tct, _ := time.Parse("2006-01-02 15:04:05", tcs)
			tc := tct.Unix()
			if compareTimeUinx(stime, endtime, tc) == -1 {//如果小于起始时间
				continue
			}
			if compareTimeUinx(stime, endtime, tc) == 1 {//如果大于结束时间
				break
			}

			for j := 1;j < colnum ;j++ {
				tcs,_ := f.GetCellValue(sheetname, itoa[j] + strconv.Itoa(i))
				buf.Write([]byte(tcs))
			}
		}
		//if bytes.Compare(buf.Bytes(), []byte("")) == 0{
		//	return nil, errors.New("没有该时间段内的数据！")
		//}
		tmpdu.Value = buf.Bytes()
		res = append(res, tmpdu)
	}
	fmt.Println()
	return res, nil
}


func (dfx *DataFacXls) GetDataHashes(stime int64, etime int64) ([]DataHashUnit, error) {
	dus, err := dfx.GetData(stime, etime)
	if err != nil {
		return nil, err
	}
	dhus := make([]DataHashUnit,len(dus))
	for i, v := range dus {
		dhus[i].Key = v.Key
		dhus[i].Name = v.Name
		dhus[i].Hvalue = v.Hash()
	}
	return dhus, nil
}