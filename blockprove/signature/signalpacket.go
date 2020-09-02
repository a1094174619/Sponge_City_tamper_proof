package signature

import (
	"bytes"
	"encoding/binary"
	"github.com/izqui/helpers"
	"fmt"
)

//goEncrypt.GetEccKey()
const(
	TIMESTAMPSIZE = 8
	TIMESIGNATURE = 165
	MERKELROOTSIZE = 32
	SIGNATURESIZE = TIMESTAMPSIZE + TIMESIGNATURE + MERKELROOTSIZE
)
type Signature struct{
	Timestamp int64
	TimeSignature []byte
	MerkelRoot []byte
}

func (sn *Signature) SetTimeSiganByRS(rtext []byte, stext []byte) (error) {
	position := len(rtext)
	l := len(rtext) + len(stext)
	a := make([]byte, TIMESIGNATURE - l , TIMESIGNATURE - l)
	la := TIMESIGNATURE - l
	
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint8(la))
	a[la-1] = buf.Bytes()[0]
	buf.Reset()

	binary.Write(buf, binary.LittleEndian, uint32(position))
	for i := 0;i < 4;i++{
		a[la-5+i] = buf.Bytes()[i]
	}
	res := append(append(rtext, stext...),a...)
	if len(res) != TIMESIGNATURE{
		fmt.Println("签名打包长度不正确")
	}
	sn.TimeSignature = res
	return nil
}

func (sn *Signature) GetRS() ([]byte, []byte) {
	buf := new(bytes.Buffer)
	buf.WriteByte(sn.TimeSignature[TIMESIGNATURE-1])
	var tail uint8
	binary.Read(buf, binary.LittleEndian, &tail)
	var position uint32
	buf.Reset()
	buf.Write(sn.TimeSignature[TIMESIGNATURE-5:TIMESIGNATURE-1][0:4])
	binary.Read(buf, binary.LittleEndian, &position)
	rtext := sn.TimeSignature[:position]
	stext := sn.TimeSignature[position:TIMESIGNATURE-tail]
	return rtext, stext
}




func (sn *Signature) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, sn.Timestamp)
	buf.Write(helpers.FitBytesInto(sn.TimeSignature, TIMESIGNATURE))
	buf.Write(helpers.FitBytesInto(sn.MerkelRoot, MERKELROOTSIZE))
	return buf.Bytes(), nil
}

func (sn *Signature) UnmarshalBinary(b []byte) error {
	buf := bytes.NewBuffer(b)
	binary.Read(bytes.NewBuffer(buf.Next(TIMESTAMPSIZE)), binary.LittleEndian, &sn.Timestamp)
	(*sn).TimeSignature = buf.Next(TIMESIGNATURE)
	(*sn).MerkelRoot = buf.Next(MERKELROOTSIZE)
	return nil
}

func (sn *Signature) MarshalBinaryProve() ([]byte, error) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, sn.Timestamp)
	buf.Write(helpers.FitBytesInto(sn.MerkelRoot, MERKELROOTSIZE))
	return buf.Bytes(), nil
}

func (sn *Signature) UnmarshalBinaryProve([]byte) error {
	buf := new(bytes.Buffer)
	binary.Read(bytes.NewBuffer(buf.Next(TIMESTAMPSIZE)), binary.LittleEndian, &sn.Timestamp)
	(*sn).MerkelRoot = buf.Next(MERKELROOTSIZE)
	return nil
}
