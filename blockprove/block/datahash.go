package block

import (
	"bytes"
	"encoding/binary"
	"github.com/izqui/helpers"
	"github.com/pkg/errors"
)

type DataHash struct {
	key uint32 //哈希的数据标号
	hash []byte //哈希值
}

func (d *DataHash) SetValues(key uint32, hash []byte) {
	d.key = key
	d.hash = hash
}

func (d *DataHash) GetValues() (key uint32, hash []byte) {
	return d.key, d.hash
}
func (d *DataHash) Hash() []byte {
	datahashBytes, _ := d.MarshalBinary()
	return helpers.SHA256(datahashBytes)
}

//将DataHash转化为二进制
func (d *DataHash) MarshalBinary() ([]byte, error) {

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, d.key)
	buf.Write(helpers.FitBytesInto(d.hash[:], DATAHASHVAL))
	return buf.Bytes(), nil
}

func (t *DataHash) UnmarshalBinary(d []byte) ([]byte, error) {

	buf := bytes.NewBuffer(d)

	if len(d) < DATAHASH {
		return  nil, errors.New("Insuficient bytes for unmarshalling DataHash")
	}
	binary.Read(bytes.NewBuffer(buf.Next(DATAHASHKEY)), binary.LittleEndian, &t.key)
	t.hash = buf.Next(DATAHASHVAL)
	return  buf.Next(helpers.MaxInt), nil

}


type DataHashSlice []DataHash

func (slice DataHashSlice) AddDataHash(d DataHash) DataHashSlice {
	return append(slice, d)
}
func (slice *DataHashSlice) GetDataHashByKey(key uint32) []byte{
	for _, v := range *slice {
		if v.key == key {
			return v.hash
		}
	}
	return nil
}

func (slice *DataHashSlice) MarshalBinary() ([]byte, error) {

	buf := new(bytes.Buffer)

	for _, t := range *slice {

		bs, err := t.MarshalBinary()

		if err != nil {
			return nil, err
		}

		buf.Write(bs)
	}

	return buf.Bytes(), nil
}

func (slice *DataHashSlice) UnmarshalBinary(d []byte) error {

	remaining := d

	for len(remaining) >= DATAHASH {
		t := new(DataHash)
		rem ,err := t.UnmarshalBinary(remaining)

		if err != nil {
			return err
		}
		(*slice) = append((*slice), *t)
		remaining = rem
	}
	return nil
}