package main

import (
	"fmt"
	"os"
	"xenproject.org/xenlight"
)

func main() {
	ctx := xenlight.Ctx
	err := ctx.Open()
	if err != nil {
		os.Exit(-1)
	}

	defer ctx.Close()
	if err != nil {
		os.Exit(-1)
	}

	free_memory, err := ctx.GetFreeMemory()
	if err != nil {
		fmt.Printf("%d\n", err)
	} else {
		fmt.Printf("%d\n", free_memory)
	}

}
