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
	info, err := ctx.GetPhysinfo()
	if err != nil {
		os.Exit(-1)
	}

	fmt.Printf("%d\n%d\n%d\n%d\n%d\n", info.ThreadsPerCore, info.CoresPerSocket,
		info.MaxCpuId, info.NrCpus, info.CpuKhz)
	fmt.Printf("%d\n%d\n%d\n%d\n%d\n%d\n", info.TotalPages, info.FreePages,
		info.ScrubPages, info.OutstandingPages, info.SharingFreedPages,
		info.SharingUsedFrames)
	fmt.Printf("%d\n", info.NrNodes)
	fmt.Printf("%t\n%t\n", info.CapHvm, info.CapHvmDirectio)

	for i := 0; i < 8; i++ {
		fmt.Printf("%d\n", info.HwCap[i])
	}
}
