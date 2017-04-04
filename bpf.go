package bpf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const bpfSysCallNum = 321 // x86_64.
const bpfInsnLen = 8
const bpfVerifierDebugBufLen = 32384

const (
	bpfCmdMapCreate     = iota
	bpfCmdMapLookupElem = iota
	bpfCmdMapUpdateElem = iota
	bpfCmdMapDeleteElem = iota
	bpfCmdMapGetNextKey = iota
	bpfCmdProgLoad      = iota
	bpfCmdObjPin        = iota
	bpfCmdObjGet        = iota
)

const (
	bpfProgTypeUnspec       = iota
	bpfProgTypeSocketFilter = iota
	bpfProgTypeKprobe       = iota
	bpfProgTypeSchedCls     = iota
	bpfProgTypeSchedAct     = iota
	bpfProgTypeTracepoint   = iota
	bpfProgTypeXdp          = iota
)

const (
	bpfMapTypeUnspec         = iota
	bpfMapTypeHash           = iota
	bpfMapTypeArray          = iota
	bpfMapTypeProgArray      = iota
	bpfMapTypePerfEventArray = iota
	bpfMapTypePerCpuHash     = iota
	bpfMapTypePerCpuArray    = iota
	bpfMapTypeStackTrace     = iota
	bpfMapTypeCgroupArray    = iota
)

type MapKey interface {
	GetDataPtr() uintptr
}

type MapEntry interface {
	GetDataPtr() uintptr
}

type bpfMapCreateAttr struct {
	mapType    uint32
	keySize    uint32
	valueSize  uint32
	maxEntries uint32
	mapFlags   uint32
}

func BpfCreateMap(mapType uint32, keySize uint32, valueSize uint32, maxEntries uint32, mapFlags uint32) (int, error) {
	attrs := bpfMapCreateAttr{}
	attrs.mapType = mapType
	attrs.keySize = keySize
	attrs.valueSize = valueSize
	attrs.maxEntries = maxEntries
	attrs.mapFlags = mapFlags

	r1, _, serr := unix.Syscall(bpfSysCallNum, uintptr(bpfCmdMapCreate), uintptr(unsafe.Pointer(&attrs)),
		uintptr(unsafe.Sizeof(attrs)))
	if serr != 0 {
		if serr == syscall.ENOMEM {
			return -1, errors.New("syscall result errno=ENOMEM")
		} else if serr == syscall.EPERM {
			return -1, errors.New("syscall result errno=EPERM")
		} else if serr == syscall.EINVAL {
			return -1, errors.New("syscall result errno=EINVAL")
		}

		// Other error of some kind.
		return -1, errors.New("syscall result unknown")
	}

	return int(r1), nil
}

type bpfMapUpdateElemAttr struct {
	fd    uint32
	key   uintptr
	value uintptr
	flags uintptr
}

// FIXME: Not complete, doesn't handle error codes.
func BpfMapUpdateElem(fd int, key MapKey, entry MapEntry, flags uint32) {
	attrs := bpfMapUpdateElemAttr{}
	attrs.fd = uint32(fd)
	//attrs.key = uintptr(unsafe.Pointer(&key))
	//attrs.value = uintptr(unsafe.Pointer(&value))
	attrs.key = key.GetDataPtr()
	attrs.value = entry.GetDataPtr()

	r1, r2, serr := unix.Syscall(bpfSysCallNum, uintptr(bpfCmdMapUpdateElem), uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Sizeof(attrs)))
	if serr != 0 {
		fmt.Println("BpfMapUpdateElem syscall failure", r1, r2, serr)
		//return -1, serr
	}
}

type bpfMapLookupElemAttr struct {
	fd    uint32
	key   uintptr
	value uintptr
	flags uintptr
}

//func BpfMapLookupElem(fd int, key interface{}) (bool, interface{}, error) {
func BpfMapLookupElem(fd int, key MapKey, entry MapEntry) (bool, error) {

	attrs := bpfMapLookupElemAttr{}
	attrs.fd = uint32(fd)
	attrs.key = key.GetDataPtr()
	attrs.value = entry.GetDataPtr()

	r1, _, serr := unix.Syscall(bpfSysCallNum, uintptr(bpfCmdMapLookupElem), uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Sizeof(attrs)))
	ret := int64(r1)

	if ret != 0 { // Error.
		if serr == syscall.ENOENT {
			// Key not found. Not really an error.
			return false, nil
		}
		return false, serr
	}

	return true, nil
}

type bpfMapDeleteElemAttr struct {
	fd    uint32
	key   uintptr
	value uintptr
	flags uintptr
}

// FIXME: Not complete, doesn't handle error codes.
func BpfMapDeleteElem(fd int, key MapKey) {
	attrs := bpfMapDeleteElemAttr{}
	attrs.fd = uint32(fd)
	attrs.key = key.GetDataPtr()

	r1, r2, serr := unix.Syscall(bpfSysCallNum, uintptr(bpfCmdMapDeleteElem), uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Sizeof(attrs)))
	if serr != 0 {
		fmt.Println("BpfMapDeleteElem syscall failure", r1, r2, serr)
		//return -1, serr
	}
}

type bpfMapGetNextKeyAttr struct {
	fd      uint32  // 4
	key     uintptr // 8
	nextKey uintptr // 8
	flags   uintptr // 8
	//pad     [48 - 28]byte
}

func BpfMapGetNextKey(fd int, key MapKey, result MapKey) (bool, error) {
	attrs := bpfMapGetNextKeyAttr{}
	attrs.fd = uint32(fd)
	attrs.key = key.GetDataPtr()
	attrs.nextKey = result.GetDataPtr()

	r1, r2, serr := unix.Syscall(bpfSysCallNum, uintptr(bpfCmdMapGetNextKey), uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Sizeof(attrs)))

	if serr != 0 {
		if serr == syscall.ENOENT {
			// The key that was search for was the last one in the map. The end.
			return false, nil
		} else if serr == syscall.EINVAL {
			fmt.Println("BpfMapGetNextKey syscall failure EINVAL:", r1, r2, serr)
			return false, serr
		} else {
			// Some other error happened.
			fmt.Println("BpfMapGetNextKey syscall failure:", r1, r2, serr)
			return false, serr
		}
	}

	return true, nil
}

type bpfProgLoadAttr struct {
	progType    uint32
	insnCnt     uint32
	insns       uintptr
	license     uintptr
	logLevel    uint32
	logSize     uint32
	logBuf      uintptr
	kernVersion uint32
}

// BpfLoadProg loads the BPF programs identified by section names from the passed ELF filename and creates any
// required BPF maps.
// On success, it returns a map from section name to Fd and a map from BPF map name to Fd and two nil error values.
// On failure, it returns two nils and one of two errors. The first error contains the BPF verifier failure (if any)
// and the second error contains the error result from the syscall or other.
func BpfLoadProg(file string, sections []string, sectionNameToFd map[string]int, mapNameToFd map[string]int) (error, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}

	elfF, err := elf.NewFile(f)
	if err != nil {
		return nil, err
	}

	// Extract the license section. This section is mandatory and is passed to the kernel.
	license := elfF.Section("license")
	if license == nil {
		return nil, errors.New("No license section found in ELF file.")
	}
	licenseData, err := license.Data()
	if err != nil {
		return nil, err
	}

	// Load the maps as defined in the "maps" ELF section.
	maps, err := bpfLoadMapsData(elfF)
	if err != nil {
		log.Println("Error loading map data: ", err)
		return nil, errors.New("Error loading map data")
	}

	// Create the maps (via BPF syscalls) and return a slice with fds that will be indexed with the symbol
	// value / size of bpfElfMap later when we do the relocations.
	mapFds, err := bpfCreateMaps(maps)
	if err != nil {
		log.Println("Error creating maps:", err)
		return nil, errors.New("Could not create BPF Maps")
	}

	for _, section := range sections {
		insns, err := getBpfInsnsFromSection(elfF, section)
		if err != nil {
			return nil, err
		}

		// Get the ELF relocation section associated with the section being loaded.
		relocSection := getElfRelatedRelocSection(elfF, section)
		if len(maps) > 0 && relocSection == nil {
			return nil, errors.New("There are maps defined but no related relocation section was found.")
		}

		// Do map relocations (if any).
		if relocSection != nil {
			relocs, err := getBpfRelocationsFromSection(elfF, relocSection)
			if err != nil {
				return nil, err
			}

			err = doBpfMapRelocation(insns, relocs, mapFds)
			if err != nil {
				return nil, err
			}

			// Build a map which goes from map_name to the fd. This will be used by the calling application to know what
			// fds to use. Note this is slightly inefficient since it hits each symbol more than once. Ahh well.
			for _, reloc := range relocs {
				mapNameToFd[reloc.name] = mapFds[reloc.value]
			}
		}

		////
		// Now that we've done all that setup work... let's do the syscall.
		////

		// Create a buffer to store errors from the in-kernel BPF verifier (if any).
		var verifierErrBuf [bpfVerifierDebugBufLen]byte

		// Build up the request.
		attrs := bpfProgLoadAttr{}
		attrs.progType = bpfProgTypeSchedCls
		attrs.insnCnt = uint32(len(insns))
		attrs.insns = uintptr(unsafe.Pointer(&insns[0]))
		attrs.license = uintptr(unsafe.Pointer(&licenseData[0]))
		attrs.logLevel = 1 // Enables verifier logging.
		attrs.logSize = uint32(len(verifierErrBuf))
		attrs.logBuf = uintptr(unsafe.Pointer(&verifierErrBuf))

		r1, _, serr := unix.Syscall(bpfSysCallNum, uintptr(bpfCmdProgLoad), uintptr(unsafe.Pointer(&attrs)),
			uintptr(unsafe.Sizeof(attrs)))
		if serr != 0 {
			e := fmt.Sprintf("Verifier error %d in section %s: %s", r1, section,
				string(verifierErrBuf[:bpfVerifierDebugBufLen]))
			verifierError := errors.New(e)
			return verifierError, serr
		}

		sectionNameToFd[section] = int(r1)
	}

	return nil, nil
}

// See bpf_elf.h in iproute2. Strictly speaking, this loader doesn't have to use the same structure as iproute2
// but it might as well.
type bpfElfMap struct {
	Type      uint32
	SizeKey   uint32
	SizeValue uint32
	MaxElem   uint32
	Flags     uint32
	Id        uint32
	Pinning   uint32
}

const bpfElfMapLen = 28 // TODO: Use SizeOf instead?

// bpfLoadMapsData extracts the details of the maps used in this eBPF program from the "maps" section
// of the ELF file. If the "maps" section is not present, it returns an empty slice.
func bpfLoadMapsData(elfF *elf.File) ([]bpfElfMap, error) {

	mapsSection := elfF.Section("maps")
	if mapsSection == nil {
		return make([]bpfElfMap, 0), nil
	}

	if mapsSection.Type != elf.SHT_PROGBITS {
		return nil, errors.New("Maps section found but is of wrong type.")
	}

	maps := make([]bpfElfMap, mapsSection.Size/bpfElfMapLen)

	data, err := mapsSection.Data()
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(data)

	err = binary.Read(buf, binary.LittleEndian, &maps)
	if err != nil {
		return nil, err
	}

	return maps, nil
}

// bpfCreateMaps takes in the map definitions as extracted from the "maps" section and creates the maps.
// It returns a slice that maps the map index, as defined in the "maps" section to the file descriptor
// that is created for that map.
func bpfCreateMaps(maps []bpfElfMap) ([]int, error) {
	fds := make([]int, 0, len(maps))

	for _, m := range maps {
		fd, err := BpfCreateMap(m.Type, m.SizeKey, m.SizeValue, m.MaxElem, m.Flags)
		if err != nil {
			return nil, err
		}

		fds = append(fds, fd)
	}

	return fds, nil
}

// getElfRelatedRelocSection returns the relocation section (SHT_REL) associated with the passed
// section name. It returns nil if one can not be found.
func getElfRelatedRelocSection(f *elf.File, section string) *elf.Section {
	var relocSection *elf.Section

	relocSections := getElfRelocSections(f)
	for _, sec := range relocSections {
		if f.Sections[sec.Info].Name == section {
			relocSection = sec
		}
	}

	return relocSection
}

// getElfRelSections gets all sections of type SHT_REL (relocation) from the passed elf.File.
// debug.elf has a SectionByType() but it only gets the first section of the passed type.
func getElfRelocSections(f *elf.File) []*elf.Section {
	var secs []*elf.Section

	for _, s := range f.Sections {
		if s.Type == elf.SHT_REL {
			secs = append(secs, s)
		}
	}

	return secs
}

// getBpfInsnsFromSection returns an array of eBPF instructions as extracted from the passed *elf.File and section
// name.
func getBpfInsnsFromSection(f *elf.File, section string) ([]bpfInsn, error) {
	sec := f.Section(section)
	if sec == nil {
		s := fmt.Sprintf("Could not find section %s", section)
		return nil, errors.New(s)
	}
	d, err := sec.Data() // d is the byte array containing the instructions.
	if err != nil {
		return nil, err
	}

	if len(d)%bpfInsnLen != 0 {
		return nil, errors.New("Something is wrong. Instructions byte array is a bad size.")
	}

	buf := bytes.NewBuffer(d)

	insns := make([]bpfInsn, len(d)/bpfInsnLen)

	err = binary.Read(buf, binary.LittleEndian, &insns)
	if err != nil {
		return nil, err
	}

	return insns, nil
}

type bpfMapRelocation struct {
	insnIdx uint64
	value   uint64
	name    string
}

// getBpfRelocationsFromSection extracts the relocations we need to perform from the passed section and does the
// symbol look ups required to determine what value will be used during the relocation.
func getBpfRelocationsFromSection(f *elf.File, section *elf.Section) ([]bpfMapRelocation, error) {
	d, _ := section.Data()
	bb := bytes.NewBuffer(d)
	const rel64Len = 16
	rel64s := make([]elf.Rel64, len(d)/rel64Len)
	err := binary.Read(bb, binary.LittleEndian, &rel64s)
	if err != nil {
		return nil, err
	}

	relocs := make([]bpfMapRelocation, 0, len(rel64s))

	for _, rel64 := range rel64s {
		reloc := bpfMapRelocation{}
		reloc.insnIdx = rel64.Off / bpfInsnLen

		symIdx := rel64.Info >> 32

		syms, err := f.Symbols()
		if err != nil {
			return nil, err
		}
		sym := syms[symIdx-1]
		reloc.value = sym.Value / bpfElfMapLen
		reloc.name = sym.Name

		relocs = append(relocs, reloc)
	}

	return relocs, nil
}

// Perform the BPF map file descriptor relocations.
func doBpfMapRelocation(insns []bpfInsn, relocs []bpfMapRelocation, mapFds []int) error {

	for _, reloc := range relocs {
		insn := &insns[reloc.insnIdx]
		insn.SetSrcReg(1) // 1 == BPF_PSEUDO_MAP_FD.
		insn.SetImm(int32(mapFds[reloc.value]))
	}

	return nil
}

type bpfObjPinAttr struct {
	pathname uintptr
	fd       uint32
}

// FIXME: Pin doesn't work yet. Don't know why.
func BpfObjPin(fd int, pathname string) error {
	attrs := bpfObjPinAttr{}
	attrs.fd = uint32(fd)

	pptr, err := unix.BytePtrFromString(pathname)
	if err != nil {
		return err
	}

	attrs.pathname = uintptr(unsafe.Pointer(pptr))

	r1, r2, serr := unix.Syscall(bpfSysCallNum, uintptr(bpfCmdObjPin), uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Sizeof(attrs)))
	if serr != 0 {
		fmt.Println("BpfObjPin syscall failure", r1, r2, serr)
		return serr
	}

	return nil
}

// TODO: UnPin
func BpfObjUnpin(fd int) error {
	return nil
}
