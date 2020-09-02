package main

import (
	"fmt"
	"github.com/izqui/helpers"
)

func main() {
	for i := 0;; i++ {
		fmt.Println(i)
		hash := helpers.SHA256([]byte(string(i)))
		hashHex, _ := fmt.Printf("%x", hash)
		fmt.Println(hashHex)
		count := 0
		for _, v := range  {
			if hash[count] != '0' {
				break
			}
		}
		if count >= 1 {
			break
		}
	}
}