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

	max_cpus, err := ctx.GetMaxCpus()
	if err != nil {
		fmt.Printf("%d\n", err)
	} else {
		fmt.Printf("%d\n", max_cpus)
	}

}
