package pe

// DOS Header
type DOS_HEADER struct {
	E_Magic    uint16     //WORD   e_magic;     Magic number
	E_Cblp     uint16     //WORD   e_cblp;      Bytes on last page of file
	E_CP       uint16     //WORD   e_cp;        Pages in file
	E_Crlc     uint16     //WORD   e_crlc;      Relocations
	E_Cparhdr  uint16     //WORD   e_cparhdr;   Size of header in paragraphs
	E_Minalloc uint16     //WORD   e_minalloc;  Minimum extra paragraphs needed
	E_Maxalloc uint16     //WORD   e_maxalloc;  Maximum extra paragraphs needed
	E_SS       uint16     //WORD   e_ss;        Initial (relative) SS value
	E_SP       uint16     //WORD   e_sp;        Initial SP value
	E_Csum     uint16     //WORD   e_csum;      Checksum
	E_IP       uint16     //WORD   e_ip;        Initial IP value
	E_CS       uint16     //WORD   e_cs;        Initial (relative) CS value
	E_Lfarlc   uint16     //WORD   e_lfarlc;    File address of relocation table
	E_Ovno     uint16     //WORD   e_ovno;      Overlay number
	E_RES      [4]uint16  //WORD   e_res[4];    Reserved words
	E_Oemid    uint16     //WORD   e_oemid;     OEM identifier (for e_oeminfo)
	E_Oeminfo  uint16     //WORD   e_oeminfo;   OEM information; e_oemid specific
	E_RES2     [10]uint16 //WORD   e_res2[10];  Reserved words
	E_LFANEW   uint32     //LONG   e_lfanew;    File address of new exe header 0x3C
}

// NT Header
type NT_HEADER struct {
	Signature      uint32
	CoffFileHeader COFF_File_HEADER
	// OptionalHeader is of type *OptionalHeader32 or *OptionalHeader64.
	OptionalHeader OptionalHeader
}

// COFF File Header
type COFF_File_HEADER struct {
	Machine              uint16 //  WORD  Machine;
	NumberOfSections     uint16 //  WORD  NumberOfSections;
	TimeDateStamp        uint32 //  DWORD TimeDateStamp;
	PointerToSymbolTable uint32 //  DWORD PointerToSymbolTable;
	NumberOfSymbols      uint32 //  DWORD NumberOfSymbols;
	SizeOfOptionalHeader uint16 //  WORD  SizeOfOptionalHeader;
	Characteristics      uint16 //  WORD  Characteristics;
}

type OptionalHeader struct {
	OptionalHeader32 OptionalHeader32
	OptionalHeader64 OptionalHeader64
}

const (
	SIZE_OF_OPTIONAL_HEADER_32 = 0xe0
	SIZE_OF_OPTIONAL_HEADER_64 = 0xf0
)

// OptionalHeader32
type OptionalHeader32 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	BaseOfData                  uint32
	ImageBase                   uint32
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint32
	SizeOfStackCommit           uint32
	SizeOfHeapReserve           uint32
	SizeOfHeapCommit            uint32
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]DataDirectory
}

// OptionalHeader64
type OptionalHeader64 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]DataDirectory
}

type DataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

const (
	IMAGE_SCN_CNT_CODE               = 0x00000020
	IMAGE_SCN_CNT_INITIALIZED_DATA   = 0x00000040
	IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
	IMAGE_SCN_LNK_COMDAT             = 0x00001000
	IMAGE_SCN_MEM_DISCARDABLE        = 0x02000000
	IMAGE_SCN_MEM_EXECUTE            = 0x20000000
	IMAGE_SCN_MEM_READ               = 0x40000000
	IMAGE_SCN_MEM_WRITE              = 0x80000000
)

// Section Header
type Section_HEADER struct {
	Name                 [8]uint8 `json:"name"`
	VirtualSize          uint32   `json:"virtual_size"`
	VirtualAddress       uint32   `json:"virtual_address"`
	SizeOfRawData        uint32   `json:"size_of_raw_data"`
	PointerToRawData     uint32   `json:"pointer_to_raw_data"`
	PointerToRelocations uint32   `json:"pointer_to_relocations"`
	PointerToLineNumbers uint32   `json:"pointer_to_line_numbers"`
	NumberOfRelocations  uint16   `json:"number_of_relocations"`
	NumberOfLineNumbers  uint16   `json:"number_of_line_numbers"`
	Characteristics      uint32   `json:"characteristics"`
}

type ExportDirectory struct {
	Characteristics       uint32 // always 0
	TimeDateStamp         uint32 // create file time
	MajorVersion          uint16 // always 0
	MinorVersion          uint16 // always 0
	Name                  uint32 // pointer of dll name ascii string rva
	Base                  uint32 // number of function
	NumberOfFunctions     uint32 // function total
	NumberOfNames         uint32 //
	AddressOfFunctions    uint32 // RVA from base of
	AddressOfNames        uint32 // RVA from base of
	AddressOfNameOrdinals uint32 // RVA from base of
}

type ImportDirectory struct {
	OriginalFirstThunk uint32
	TimeDateStamp      uint32
	ForwarderChain     uint32
	Name               uint32
	FirstThunk         uint32
}

type ImageExportDirectory struct {
	Characteristics       uint32 // always 0
	TimeDateStamp         uint32 // create file time
	MajorVersion          uint16 // always 0
	MinorVersion          uint16 // always 0
	Name                  uint32 // pointer of dll name ascii string rva
	Base                  uint32 // number of function
	NumberOfFunctions     uint32 // function total
	NumberOfNames         uint32 //
	AddressOfFunctions    uint32 // RVA from base of image
	AddressOfNames        uint32 // RVA from base of image
	AddressOfNameOrdinals uint32 // RVA from base of image
}

type ImageImportDirectory struct {
	OriginalFirstThunk uint32
	TimeDateStamp      uint32
	ForwarderChain     uint32
	Name               uint32
	FirstThunk         uint32
}
