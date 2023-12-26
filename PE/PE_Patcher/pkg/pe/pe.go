package pe

import (
	"debug/pe"
)

// PE Header
type PEFile struct {
	RawSourceBytes []byte
	DOSHeader      *DOS_HEADER
	//DOSStub          *Rich_Header
	NTHeader         *NT_HEADER
	OptionalHeader32 *pe.OptionalHeader32
	OptionalHeader64 *pe.OptionalHeader64
	SectionHeaders   []*Section_HEADER
}
