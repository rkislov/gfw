//go:build linux

package xdpguard

import "github.com/cilium/ebpf/asm"

const (
	sourceKey      = -24
	destinationKey = -48
	counterKey     = -52
)

// program inspects Ethernet, at most two VLAN headers, and IP addresses.
// The only terminal verdicts are XDP_PASS (2) and XDP_DROP (1).
func program(match string, manual, supplied, exceptions bool, manualFD, feedFD, exceptFD, counterFD int) asm.Instructions {
	ins := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadMem(asm.R2, asm.R6, 0, asm.Word),
		asm.LoadMem(asm.R3, asm.R6, 4, asm.Word),
		asm.Mov.Reg(asm.R7, asm.R3), asm.Sub.Reg(asm.R7, asm.R2),
	}
	ins = append(ins, etherType(14, "ethernet")...)
	ins = append(ins, asm.JEq.Imm(asm.R4, 0x8100, "tag1"), asm.JEq.Imm(asm.R4, 0x88a8, "tag1"), asm.Ja.Label("ip"))
	ins = append(ins, etherType(4, "tag1")...)
	ins = append(ins, asm.JEq.Imm(asm.R4, 0x8100, "tag2"), asm.JEq.Imm(asm.R4, 0x88a8, "tag2"), asm.Ja.Label("ip"))
	ins = append(ins, etherType(4, "tag2")...)
	ins = append(ins,
		asm.JEq.Imm(asm.R4, 0x0800, "ipv4").WithSymbol("ip"),
		asm.JEq.Imm(asm.R4, 0x86dd, "ipv6"), asm.Ja.Label("passed"),
	)
	ins = append(ins, ipKeys(4, 20, 12, 16, "ipv4")...)
	ins = append(ins, ipKeys(6, 40, 8, 24, "ipv6")...)
	ins = append(ins, asm.Mov.Imm(asm.R9, 0).WithSymbol("classify"))
	if match != "destination" {
		ins = append(ins, lookupAddress(sourceKey, "after_source", manual, supplied, exceptions, manualFD, feedFD, exceptFD)...)
		ins = append(ins, asm.Mov.Reg(asm.R9, asm.R9).WithSymbol("after_source"))
	}
	if match != "source" {
		ins = append(ins, lookupAddress(destinationKey, "passed", manual, supplied, exceptions, manualFD, feedFD, exceptFD)...)
	}
	ins = append(ins,
		asm.Mov.Imm(asm.R9, 0).WithSymbol("passed"), asm.Ja.Label("stats"),
		asm.Mov.Imm(asm.R9, 1).WithSymbol("manual_drop"), asm.Ja.Label("stats"),
		asm.Mov.Imm(asm.R9, 2).WithSymbol("feed_drop"),
		asm.LoadMem(asm.R1, asm.R6, 12, asm.Word).WithSymbol("stats"),
		asm.StoreMem(asm.RFP, counterKey, asm.R1, asm.Word),
	)
	ins = append(ins, mapLookup(counterKey, counterFD)...)
	return append(ins,
		asm.JEq.Imm(asm.R0, 0, "verdict"),
		asm.JEq.Imm(asm.R9, 1, "manual_count"), asm.JEq.Imm(asm.R9, 2, "feed_count"),
		asm.Ja.Label("count"),
		asm.Add.Imm(asm.R0, 16).WithSymbol("manual_count"), asm.Ja.Label("count"),
		asm.Add.Imm(asm.R0, 32).WithSymbol("feed_count"),
		asm.Mov.Imm(asm.R1, 1).WithSymbol("count"),
		asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
		asm.Add.Imm(asm.R0, 8),
		asm.StoreXAdd(asm.R0, asm.R7, asm.DWord),
		asm.JEq.Imm(asm.R9, 0, "allow").WithSymbol("verdict"),
		asm.Mov.Imm(asm.R0, 1), asm.Return(),
		asm.Mov.Imm(asm.R0, 2).WithSymbol("allow"), asm.Return(),
	)
}

func etherType(size int16, label string) asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R4, asm.R2).WithSymbol(label), asm.Add.Imm(asm.R4, int32(size)),
		asm.JGT.Reg(asm.R4, asm.R3, "passed"),
		asm.LoadMem(asm.R4, asm.R2, size-2, asm.Half),
		asm.HostTo(asm.BE, asm.R4, asm.Half),
		asm.Add.Imm(asm.R2, int32(size)),
	}
}

func ipKeys(family, size, src, dst int16, label string) asm.Instructions {
	ins := asm.Instructions{
		asm.Mov.Reg(asm.R4, asm.R2).WithSymbol(label), asm.Add.Imm(asm.R4, int32(size)),
		asm.JGT.Reg(asm.R4, asm.R3, "passed"),
		asm.LoadMem(asm.R4, asm.R2, 0, asm.Byte),
		asm.Mov.Reg(asm.R5, asm.R4), asm.RSh.Imm(asm.R5, 4),
		asm.JNE.Imm(asm.R5, int32(family), "passed"),
	}
	words := 4
	if family == 4 {
		words = 1
		ins = append(ins, asm.And.Imm(asm.R4, 15), asm.JLT.Imm(asm.R4, 5, "passed"))
	}
	for _, key := range []struct{ stack, packet int16 }{{sourceKey, src}, {destinationKey, dst}} {
		ins = append(ins,
			asm.StoreImm(asm.RFP, key.stack, int64(32+words*32), asm.Word),
			asm.StoreImm(asm.RFP, key.stack+4, int64(family), asm.Word),
		)
		for i := range 4 {
			offset := int16(i * 4)
			if i < words {
				ins = append(ins, asm.LoadMem(asm.R4, asm.R2, key.packet+offset, asm.Word), asm.StoreMem(asm.RFP, key.stack+8+offset, asm.R4, asm.Word))
			} else {
				ins = append(ins, asm.StoreImm(asm.RFP, key.stack+8+offset, 0, asm.Word))
			}
		}
	}
	return append(ins, asm.Ja.Label("classify"))
}

func mapLookup(offset int32, fd int) asm.Instructions {
	return asm.Instructions{
		asm.LoadMapPtr(asm.R1, fd),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, offset), asm.FnMapLookupElem.Call(),
	}
}

func lookupAddress(key int32, next string, manual, supplied, exceptions bool, manualFD, feedFD, exceptFD int) asm.Instructions {
	var ins asm.Instructions
	if manual {
		ins = append(ins, mapLookup(key, manualFD)...)
		ins = append(ins, asm.JNE.Imm(asm.R0, 0, "manual_drop"))
	}
	if supplied {
		ins = append(ins, mapLookup(key, feedFD)...)
		ins = append(ins, asm.JEq.Imm(asm.R0, 0, next))
		if exceptions {
			ins = append(ins, mapLookup(key, exceptFD)...)
			ins = append(ins, asm.JNE.Imm(asm.R0, 0, next))
		}
		ins = append(ins, asm.Ja.Label("feed_drop"))
	}
	return ins
}
