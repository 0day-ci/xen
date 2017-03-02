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
	info, err := ctx.DomainInfo(0)
	if err != nil {
		os.Exit(-1)
	}

	fmt.Printf("%d\n%d\n", info.Domid, info.Ssidref)
	//fmt.Printf("%s\n", info.SsidLabel)
	fmt.Printf("%t\n%t\n%t\n%t\n%t\n%t\n", info.Running,
		info.Blocked, info.Paused, info.Shutdown, info.Dying, info.NeverStop)
	cpuTime := info.CpuTime / (1 << 35)
	fmt.Printf("%d\n%d\n%d\n%d\n%d\n%d\n%d\n%d\n%d\n%d\n", info.ShutdownReason, info.OutstandingMemkb,
		info.CurrentMemkb, info.SharedMemkb, info.PagedMemkb, info.MaxMemkb, cpuTime,
		info.VcpuMaxId, info.VcpuOnline, info.Cpupool)
	fmt.Printf("%d\n", info.DomainType)

}
