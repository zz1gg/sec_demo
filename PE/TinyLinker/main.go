package main

import (
	"fmt"
	"github.com/saferwall/pe"
	"log"
	"os"
	"unsafe"
)

const (
	SIZE_OF_OPTIONAL_HEADER_32 = 0xe0
	SIZE_OF_OPTIONAL_HEADER_64 = 0xf0
)

func main() {

	var shellcode = []byte{0x31, 0xd2, 0xb2, 0x30, 0x64, 0x8b, 0x12, 0x8b, 0x52, 0x0c, 0x8b, 0x52, 0x1c, 0x8b, 0x42,
		0x08, 0x8b, 0x72, 0x20, 0x8b, 0x12, 0x80, 0x7e, 0x0c, 0x33, 0x75, 0xf2, 0x89, 0xc7, 0x03,
		0x78, 0x3c, 0x8b, 0x57, 0x78, 0x01, 0xc2, 0x8b, 0x7a, 0x20, 0x01, 0xc7, 0x31, 0xed, 0x8b,
		0x34, 0xaf, 0x01, 0xc6, 0x45, 0x81, 0x3e, 0x46, 0x61, 0x74, 0x61, 0x75, 0xf2, 0x81, 0x7e,
		0x08, 0x45, 0x78, 0x69, 0x74, 0x75, 0xe9, 0x8b, 0x7a, 0x24, 0x01, 0xc7, 0x66, 0x8b, 0x2c,
		0x6f, 0x8b, 0x7a, 0x1c, 0x01, 0xc7, 0x8b, 0x7c, 0xaf, 0xfc, 0x01, 0xc7, 0x68, 0x79, 0x74,
		0x65, 0x01, 0x68, 0x6b, 0x65, 0x6e, 0x42, 0x68, 0x20, 0x42, 0x72, 0x6f, 0x89, 0xe1, 0xfe,
		0x49, 0x0b, 0x31, 0xc0, 0x51, 0x50, 0xff, 0xd7}

	pefile := new(pe.File)

	peHeaderSize := P2ALIGNUP(uint32(unsafe.Sizeof(pefile.DOSHeader)+unsafe.Sizeof(pefile.NtHeader)+unsafe.Sizeof(pefile.Sections)), file_align)

	log.Println("peHeaderSize:", peHeaderSize)

	sectionData := P2ALIGNUP(uint32(len(shellcode)), file_align)
	log.Println("peHeaderSize:", sectionData)

	peData := make([]byte, peHeaderSize+sectionData)

	//DOS

	dosHdr := (*pe.ImageDOSHeader)(unsafe.Pointer(&peData[0]))
	dosHdr.Magic = pe.ImageDOSSignature
	dosHdr.AddressOfNewEXEHeader = uint32(unsafe.Sizeof(pefile.DOSHeader))

	//NT
	ntHdr := (*pe.ImageNtHeader)(unsafe.Pointer(&peData[dosHdr.AddressOfNewEXEHeader]))

	ntHdr.Signature = pe.ImageNTSignature

	ntHdr.FileHeader.Machine = pe.ImageFileMachineI386

	ntHdr.FileHeader.Characteristics = pe.ImageFileExecutableImage | pe.ImageFile32BitMachine
	optionalHeader32Offset := int64(dosHdr.AddressOfNewEXEHeader) + int64(24)

	ntHdr.FileHeader.SizeOfOptionalHeader = SIZE_OF_OPTIONAL_HEADER_32

	ntHdr.FileHeader.NumberOfSections = 1

	//section

	sectHdr := (*pe.ImageSectionHeader)(unsafe.Pointer(&peData[int64(unsafe.Sizeof(pe.ImageOptionalHeader32{}))+optionalHeader32Offset]))
	sectHdr.Name = [8]byte{'.', 't', 'e', 's', 't', '.', 'w', 'j'}
	sectHdr.VirtualAddress = 0x1000
	sectHdr.VirtualSize = P2ALIGNUP(uint32(len(shellcode)), sect_align)
	sectHdr.SizeOfRawData = uint32(len(shellcode))
	sectHdr.PointerToRawData = peHeaderSize
	sectHdr.Characteristics = pe.ImageSectionMemExecute | pe.ImageSectionMemRead | pe.ImageSectionMemWrite

	//optionalHeader

	optHeader := (*pe.ImageOptionalHeader32)(unsafe.Pointer(&peData[int64(dosHdr.AddressOfNewEXEHeader)+int64(24)]))

	optHeader.AddressOfEntryPoint = sectHdr.VirtualAddress
	optHeader.Magic = pe.ImageNtOptionalHeader32Magic
	optHeader.BaseOfCode = sectHdr.VirtualAddress //.text RVA
	optHeader.BaseOfData = 0x0000                 //.data RVA
	optHeader.ImageBase = 0x400000
	optHeader.FileAlignment = file_align
	optHeader.SectionAlignment = sect_align
	//optHeader.Subsystem = pe.ImageSubsystemWindowsCUI //console
	optHeader.Subsystem = pe.ImageSubsystemWindowsGUI //no console
	optHeader.SizeOfImage = sectHdr.VirtualAddress + sectHdr.VirtualSize
	optHeader.SizeOfHeaders = peHeaderSize
	optHeader.MajorSubsystemVersion = 5
	optHeader.MinorSubsystemVersion = 1

	addshellcode := make([]byte, P2ALIGNUP(uint32(len(shellcode)), file_align))

	copy(addshellcode, shellcode)

	copy(peData[sectHdr.PointerToRawData:], shellcode)

	// save to disk
	f, err := os.Create("test.exe")
	if err != nil {
		panic(err)
	}
	//New PE
	f.Write(peData)
	defer f.Close()
	fmt.Printf("[+] Create New PE File: %s \n", f.Name())

}

func P2ALIGNUP(size, align uint32) uint32 {

	return (size + align - 1) &^ (align - 1)

}

const (
	file_align = 0x200
	sect_align = 0x1000
)
