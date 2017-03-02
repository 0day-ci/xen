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
	info, err := ctx.GetVersionInfo()
	if err != nil {
		os.Exit(-1)
	}

	fmt.Printf("%d\n%d\n", info.XenVersionMajor, info.XenVersionMinor)
	fmt.Printf("%s\n%s\n%s\n%s\n%s\n%s\n%s\n", info.XenVersionExtra, info.Compiler,
		info.CompileBy, info.CompileDomain, info.CompileDate, info.Capabilities,
		info.Changeset)
	fmt.Printf("%d\n%d\n", info.VirtStart, info.Pagesize)
	fmt.Printf("%s\n%s\n", info.Commandline, info.BuildId)

}
