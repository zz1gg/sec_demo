package pe

import (
	"debug/pe"
	"unsafe"
)

func GetDOSHeader(f []byte) *DOS_HEADER {
	return (*DOS_HEADER)(unsafe.Pointer(&f[0]))
}

func GetNtHeader(f []byte) *NT_HEADER {

	return (*NT_HEADER)(unsafe.Pointer(&f[GetDOSHeader(f).E_LFANEW]))

}

func GetFileHeader(f []byte) *COFF_File_HEADER {

	return &GetNtHeader(f).CoffFileHeader
}
func GetOptHeader32(f []byte) *pe.OptionalHeader32 {
	dos := GetDOSHeader(f)

	offset := int64(dos.E_LFANEW) + int64(24)

	return (*pe.OptionalHeader32)(unsafe.Pointer(&f[offset]))
}
func GetOptHeader64(f []byte) *pe.OptionalHeader64 {

	dos := GetDOSHeader(f)

	offset := int64(dos.E_LFANEW) + int64(24)

	return (*pe.OptionalHeader64)(unsafe.Pointer(&f[offset]))
}

func GetSectionArr(f []byte) []*Section_HEADER {
	dosh := GetDOSHeader(f)
	fh := GetFileHeader(f)
	var sections []*Section_HEADER

	var opOffset int64
	size := GetNtHeader(f).CoffFileHeader.SizeOfOptionalHeader
	if size == 0xe0 {
		opOffset = int64(unsafe.Sizeof(pe.OptionalHeader32{}))
	} else {
		opOffset = int64(unsafe.Sizeof(pe.OptionalHeader64{}))
	}

	for i := int64(0); i < int64(fh.NumberOfSections); i++ {
		offset := int64(dosh.E_LFANEW) + int64(24) + opOffset + i*int64(unsafe.Sizeof(Section_HEADER{}))
		section := (*Section_HEADER)(unsafe.Pointer(&f[offset]))
		sections = append(sections, section)
		//log.Printf("sections Arr [%d]:%x\n", i, sections[i])
	}

	return sections
}
