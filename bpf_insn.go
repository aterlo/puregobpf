package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
)

////
// BPF instruction classes
// See include/uapi/linux/bpf.h in the Linux tree.
////

const bpfInsnClassAlu64 = 0x07 // alu mode in double word width

// ld/ldx fields
const bpfInsnClassDw = 0x18   // double word
const bpfInsnClassXadd = 0xc0 // exclusive add

// alu/jmp fields
const bpfInsnClassMov = 0xb0  // mov reg to reg
const bpfInsnClassArsh = 0xc0 // sign extending arithmetic shift right

// change endianness of a register
const bpfInsnClassEnd = 0xd0  // flags for endianness conversion:
const bpfInsnClassToLe = 0x00 // convert to little-endian
const bpfInsnClassToBe = 0x08 // convert to big-endian
const bpfInsnClassFromLe = bpfInsnClassToLe
const bpfInsnClassFromBe = bpfInsnClassToBe

const bpfInsnClassJne = 0x50  // jump !=
const bpfInsnClassJsgt = 0x60 // SGT is signed '>', GT in x86
const bpfInsnClassJsge = 0x70 // SGE is signed '>=', GE in x86
const bpfInsnClassCall = 0x80 // Function call
const bpfInsnClassExit = 0x90 // Function return

type bpfInsn struct {
	Code   uint8 // Opcode
	Regs   uint8 // Src and Dest registers (C: src_reg:4, dst_reg:4)
	Offset int16 // Signed offset
	Imm    int32 // Signed immediate constant
}

func (insn *bpfInsn) SetSrcReg(value uint8) {
	dstReg := insn.Regs & 0xF

	insn.Regs = (value << 4) | dstReg
}

func (insn *bpfInsn) SetImm(value int32) {
	insn.Imm = value
}

func printInsn(insn bpfInsn) {
	fmt.Println("-----")
	if insn.Code&bpfInsnClassAlu64 != 0 {
		fmt.Println("Class ALU64")
	}
	fmt.Printf("\tCode: %X\n", insn.Code)
	fmt.Printf("\tRegs: %X\n", insn.Regs)
	fmt.Printf("\tOffset: %X\n", insn.Offset)
	fmt.Printf("\tImm: %X\n", insn.Imm)
}

func BpfPrintInsns(file string, section string) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}

	elfF, err := elf.NewFile(f)
	if err != nil {
		return "", err
	}

	//sections := elf.Sections()
	//elf.SectionByType()
	for idx, section := range elfF.Sections {
		fmt.Println("@@@@@@@@@@@@@@@@@ INDEX: ", idx)
		if section.Type == elf.SHT_REL {
			fmt.Println("SHT_REL SECTION ----------------")
			fmt.Println("Type:", section.Type)
			fmt.Println("Name:", section.Name)
			fmt.Println("Size:", section.Size)
			fmt.Println("EntSize:", section.Entsize)
			fmt.Println("0--0------")
			d, _ := section.Data()
			fmt.Println("Data len:", len(d))
			bb := bytes.NewBuffer(d)
			rel64 := elf.Rel64{}
			binary.Read(bb, binary.LittleEndian, &rel64)
			fmt.Println("Rel64 off:", rel64.Off)
			fmt.Println("Instruction #:", rel64.Off/bpfInsnLen)
			fmt.Println("Rel64 info:", rel64.Info)
			fmt.Printf("Rel64 info binary: %b\n", rel64.Info)
			fmt.Println("Rel64 sym (I think): ", rel64.Info>>32)
			// TODO: Remember note in doc!!! symbols is off by one in Go Elf.
			fmt.Println("Rel64 info data:", (rel64.Info<<32)>>40)
			fmt.Println("Rel64 info id:", (rel64.Info<<56)>>56)
		} else if section.Type == elf.SHT_STRTAB {
			fmt.Println("SHT_STRTAB SECTION --------------")
			fmt.Println("Type:", section.Type)
			fmt.Println("Name:", section.Name)
			fmt.Println("Size:", section.Size)
			fmt.Println("EntSize:", section.Entsize)
			fmt.Println("0--0------")
			fmt.Println(section.Data())
			st, _ := section.Data()
			for i, b := range st {
				if b != 0 {
					fmt.Printf("%d - %c\n", i, b)
				} else {
					fmt.Printf("@@@\n")
				}
			}
		} else {
			fmt.Println("Type:", section.Type)
			fmt.Println("Name:", section.Name)
			fmt.Println("Size:", section.Size)
			fmt.Println("EntSize:", section.Entsize)
			fmt.Println("0--0------")
		}
	}
	fmt.Println(elfF.DynamicSymbols())
	fmt.Println(elfF.ImportedSymbols())
	fmt.Println(elfF.ImportedLibraries())
	fmt.Println("Symbols")
	fmt.Println(elfF.Symbols())
	sym, err := elfF.Symbols()
	for si, s := range sym {
		fmt.Println("-- sym --")
		fmt.Println("sym index:", si)
		fmt.Println("Name:", s.Name)
		fmt.Println("Info:", s.Info)
		fmt.Println("Other:", s.Other)
		fmt.Println("Section:", s.Section)
		fmt.Println("Value:", s.Value)
		fmt.Println(s.Size)
		fmt.Println("----")
	}

	// Read the section the user asked for.
	sec := elfF.Section(section)
	if sec == nil {
		s := fmt.Sprintf("Could not find section %s in file %s", section, file)
		return "", errors.New(s)
	}
	d, err := sec.Data()
	if err != nil {
		return "", err
	}
	fmt.Println(len(d))

	buf := bytes.NewBuffer(d)

	insns := make([]bpfInsn, len(d)/bpfInsnLen, len(d)/bpfInsnLen)
	fmt.Println("DD:", len(insns))
	err = binary.Read(buf, binary.LittleEndian, insns)
	if err != nil {
		fmt.Println("Could not read instructions:", err)
	}

	fmt.Println("Instruction count:", len(insns))

	//return "", nil
	for _, insn := range insns {
		printInsn(insn)
	}

	return "", nil
}
