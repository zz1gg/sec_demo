package main

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"time"
)

const seekStart = 0

// Parse PE File
func PEParser(f *os.File) {
	//Successfully read the PE file and initiated parsing.
	pefile, err := pe.NewFile(f) //Create a novel file for accessing the PE binary within the underlying reader.
	if err != nil {
		log.Fatalln("[!] PE Binary broken or invalid? error: ", err)
	}

	defer pefile.Close()

	//Read the DOS segment.(DOS Header+ DOS stub)
	dosHeader := make([]byte, 96)
	//dos_signature_sizeOffset := make([]byte, 4)
	pe_signature_sizeOffset := make([]byte, 4)
	//Decimal to ASCII conversion (searching for 'MZ').
	_, err = f.Read(dosHeader)

	if err != nil {
		log.Fatalln("[!] Read DOS Header Failed with: ", err)
	}
	fmt.Println("[--------DOS Header / Stub--------]")
	fmt.Printf("[+] DOS Header's Magic Value: %s %s\n", string(dosHeader[0]), string(dosHeader[1]))
	fmt.Printf("[+] DOS Header's Magic Hex Value: %#x\n", dosHeader[0:2])
	pe_sig_offset := int64(binary.LittleEndian.Uint32(dosHeader[0x3c:]))

	fmt.Printf("[+] DOS Header's e_lfanew Value: %#x\n", pe_sig_offset)

	_, err = f.ReadAt(pe_signature_sizeOffset[:], pe_sig_offset)
	if err != nil {
		log.Println("[!] Read PE Signature Failed: ", err)
	}
	fmt.Println("")
	fmt.Println("[----------PE Signature----------]")
	fmt.Printf("[+] LEANEW Value: %s\n", string(pe_signature_sizeOffset))
	fmt.Printf("[+] PE Signature's Hex Value: %#x\n", pe_signature_sizeOffset)

	//read NT Header)

	sr := io.NewSectionReader(f, 0, 1<<63-1)
	_, err = sr.Seek(pe_sig_offset+4, seekStart)
	if err != nil {
		log.Println(err)
	}
	//binary.Read(sr, binary.LittleEndian, &pefile.FileHeader)

	if err := binary.Read(sr, binary.LittleEndian, &pefile.FileHeader); err != nil {
		log.Println(err)
	}

	// Parsing the COFF header, 20 bytes
	fmt.Println("")
	fmt.Println("[----------COFF File Header----------]")
	fmt.Printf("[+] Machine Architecture: %#x\n", pefile.FileHeader.Machine)
	fmt.Printf("[+] Number Of Sections: %#x => %s\n", pefile.FileHeader.NumberOfSections, strconv.Itoa(int(pefile.FileHeader.NumberOfSections)))
	fmt.Printf("[+] TimeDateStamp: %#x => %s\n", pefile.FileHeader.TimeDateStamp, time.Unix(int64(pefile.FileHeader.TimeDateStamp), 0))
	fmt.Printf("[+] PointerToSymbolTable: %#x\n", pefile.FileHeader.PointerToSymbolTable)
	fmt.Printf("[+] NumberOfSymbols: %#x\n", pefile.NumberOfSymbols)
	fmt.Printf("[+] SizeOfOptionalHeader: %#x => %s\n", pefile.FileHeader.SizeOfOptionalHeader, strconv.Itoa(int(pefile.FileHeader.SizeOfOptionalHeader)))
	fmt.Printf("[+] Characteristics: %#x\n", pefile.Characteristics)

	//

	// Reading the Optional Header

	//
	var sizeofOptionalHeader32 = uint16(binary.Size(pe.OptionalHeader32{}))
	var sizeofOptionalHeader64 = uint16(binary.Size(pe.OptionalHeader64{}))

	var oh32 pe.OptionalHeader32
	var oh64 pe.OptionalHeader64

	switch pefile.FileHeader.SizeOfOptionalHeader {
	case sizeofOptionalHeader32:

		if err := binary.Read(sr, binary.LittleEndian, &oh32); err != nil {
			log.Println(err)
		}

		fmt.Println("")
		fmt.Println("[----------Optional Header----------]")
		fmt.Printf("[+] Entry Point: %#x\n", oh32.AddressOfEntryPoint)
		fmt.Printf("[+] ImageBase: %#x\n", oh32.ImageBase)
		fmt.Printf("[+] Section Alignment: %#x\n", oh32.SectionAlignment)
		fmt.Printf("[+] File Alignment: %#x\n", oh32.FileAlignment)
		fmt.Printf("[+] Size Of Image: %#x\n", oh32.SizeOfImage)
		fmt.Printf("[+] Size Of Headers: %#x\n", oh32.SizeOfHeaders)
		fmt.Printf("[+] Checksum: %#x\n", oh32.CheckSum)
		fmt.Printf("[+] Subsystem: %#x\n", oh32.Subsystem)
		fmt.Printf("[+] DLLCharacteristics: %#x\n", oh32.DllCharacteristics)
		fmt.Printf("[+] DataDirectory: %#x\n", oh32.DataDirectory)
		fmt.Println("\t[----------Data Directory Offsets----------]")
		fmt.Printf("\t#ID - \tVirtualAddress - \t\tIMAGE_DIRECTORY_Name - \tSize \n")

		var winnt_datadirs = []string{
			"Export Directory - Export Table",
			"Import Directory - Import Table",
			"Resource Directory - Resource Table",
			"Exception Directory - Exception Handling Function Table",
			"Security Directory - Authenticode Signature Verification Table",
			"Base Relocation Table - Base Address Relocation Table",
			"Debug Directory - Debug Data Table",
			"Architecture-specific data - Reserved as 0 (currently deprecated)",
			"Global Pointer directory index - Index of the Global Pointer Directory (currently deprecated)",
			"Thread Local Storage (TLS) - Thread Local Storage Table",
			"Load Configuration Directory - Load Configuration Directory",
			"Bound Import Directory in headers - Bound Import Directory in headers",
			"Import Address Table - Global Import Function Pointer Table",
			"Delay Load Import Descriptors - Delay Load Import Function Table",
			"COM Runtime Descriptor - .Net Structure Table",
			"Reserved - System Reserved.",
		}
		for idx, directory := range oh32.DataDirectory {
			//fmt.Printf("[!] Data Directory: %s\n", winnt_datadirs[idx])
			//fmt.Printf("[+] Image Virtual Address: %#x\n", directory.VirtualAddress)
			//fmt.Printf("[+] Image Size: %#x\n", directory.Size)
			fmt.Printf("\t#%02d - %-20s - \t%.8x - %.8x \n", idx, winnt_datadirs[idx], directory.VirtualAddress, directory.Size)

		}

		//print section info
		fmt.Println("")
		fmt.Println("[-----Section Table(Section  Header)-----]")
		fmt.Printf("\t#ID - \tSection Name - \tPointerToRawData. - SizeOfRawData - VirtualSize - Next Section Offset \n")
		for i, section := range pefile.Sections {
			fmt.Printf("\t#%02d - %-20s - %.8x - %.8x - %#.8x - \t%#.8x \n", i, section.Name, section.Offset, section.Size, section.VirtualSize, section.Offset+section.Size)

			/*
				fmt.Println("[+] --------------------")
				fmt.Printf("[+] Section Name: %s\n", section.Name)
				fmt.Printf("[+] Section Characteristics: %#x\n", section.Characteristics)
				fmt.Printf("[+] Section Virtual Size: %#x\n", section.VirtualSize)
				fmt.Printf("[+] Section Virtual Offset: %#x\n", section.VirtualAddress)
				fmt.Printf("[+] Section Raw Size: %#x\n", section.Size)
				fmt.Printf("[+] Section Raw Offset to Data: %#x\n", section.Offset)
				fmt.Printf("[+] Section Append Offset (Next Section): %#x\n", section.Offset+section.Size)
			*/
		}

		//Printing section offset information.
		fmt.Println("[----------Section Offsets----------]")
		fmt.Printf("[+][+] Number Of Sections Field Offset: %#x\n", pe_sig_offset+4+2) //Offset value of PE signature + 4 bytes + 2 bytes = Offset value of NumberOfSections
		fmt.Printf("[+][+] Section Table Offset: %#x\n", pe_sig_offset+0xF8)           //0xF8 => 248

	// Retrieving the Optional Header

	// Enumerating section data
	case sizeofOptionalHeader64:
		if err := binary.Read(sr, binary.LittleEndian, &oh64); err != nil {
			log.Println(err)
		}

		fmt.Println("")
		fmt.Println("[----------Optional Header----------]")
		fmt.Printf("[+] Entry Point: %#x\n", oh64.AddressOfEntryPoint)
		fmt.Printf("[+] ImageBase: %#x\n", oh64.ImageBase)
		fmt.Printf("[+] Section Alignment: %#x\n", oh64.SectionAlignment)
		fmt.Printf("[+] File Alignment: %#x\n", oh64.FileAlignment)
		fmt.Printf("[+] Size Of Image: %#x\n", oh64.SizeOfImage)
		fmt.Printf("[+] Size Of Headers: %#x\n", oh64.SizeOfHeaders)
		fmt.Printf("[+] Checksum: %#x\n", oh64.CheckSum)
		fmt.Printf("[+] Subsystem: %#x\n", oh64.Subsystem)
		fmt.Printf("[+] DLLCharacteristics: %#x\n", oh64.DllCharacteristics)
		fmt.Printf("[+] DataDirectory: %#x\n", oh64.DataDirectory)
		fmt.Println("\t[----------Data Directory Offsets----------]")
		fmt.Printf("\t#ID - \tVirtualAddress - \t\tIMAGE_DIRECTORY_Name - \tSize \n")

		var winnt_datadirs = []string{
			"Export Directory - Export Table",
			"Import Directory - Import Table",
			"Resource Directory - Resource Table",
			"Exception Directory - Exception Handling Function Table",
			"Security Directory - Authenticode Signature Verification Table",
			"Base Relocation Table - Base Address Relocation Table",
			"Debug Directory - Debug Data Table",
			"Architecture-specific data - Reserved as 0 (currently deprecated)",
			"Global Pointer directory index - Index of the Global Pointer Directory (currently deprecated)",
			"Thread Local Storage (TLS) - Thread Local Storage Table",
			"Load Configuration Directory - Load Configuration Directory",
			"Bound Import Directory in headers - Bound Import Directory in headers",
			"Import Address Table - Global Import Function Pointer Table",
			"Delay Load Import Descriptors - Delay Load Import Function Table",
			"COM Runtime Descriptor - .Net Structure Table",
			"Reserved - System Reserved.",
		}
		for idx, directory := range oh64.DataDirectory {
			//fmt.Printf("[!] Data Directory: %s\n", winnt_datadirs[idx])
			//fmt.Printf("[+] Image Virtual Address: %#x\n", directory.VirtualAddress)
			//fmt.Printf("[+] Image Size: %#x\n", directory.Size)
			fmt.Printf("\t#%02d - %-20s - \t%.8x - %.8x \n", idx, winnt_datadirs[idx], directory.VirtualAddress, directory.Size)

		}

		// Printing section information
		fmt.Println("")
		fmt.Println("[-----Section Table(Section  Header)-----]")
		fmt.Printf("\t#ID - \tSection Name - \tPointerToRawData. - SizeOfRawData - VirtualSize - Next Section Offset \n")
		for i, section := range pefile.Sections {
			fmt.Printf("\t#%02d - %-20s - %.8x - %.8x - %#.8x - \t%#.8x \n", i, section.Name, section.Offset, section.Size, section.VirtualSize, section.Offset+section.Size)

			/*
				fmt.Println("[+] --------------------")
				fmt.Printf("[+] Section Name: %s\n", section.Name)
				fmt.Printf("[+] Section Characteristics: %#x\n", section.Characteristics)
				fmt.Printf("[+] Section Virtual Size: %#x\n", section.VirtualSize)
				fmt.Printf("[+] Section Virtual Offset: %#x\n", section.VirtualAddress)
				fmt.Printf("[+] Section Raw Size: %#x\n", section.Size)
				fmt.Printf("[+] Section Raw Offset to Data: %#x\n", section.Offset)
				fmt.Printf("[+] Section Append Offset (Next Section): %#x\n", section.Offset+section.Size)
			*/
		}

		//Printing section offset information.
		fmt.Println("[----------Section Offsets----------]")
		fmt.Printf("[+][+] Number Of Sections Field Offset: %#x\n", pe_sig_offset+4+2) //PE签名的偏移值+4字节+2字节=NumberOfSections偏移值
		fmt.Printf("[+][+] Section Table Offset: %#x\n", pe_sig_offset+0xF8)           //0xF8 => 248

	}

}

func main() {

	// Failed to retrieve command line parameters

	// Reading PE file
	// Failed to retrieve command line parameters
	if len(os.Args) != 2 {
		log.Fatalln("[!] usage: ./PE_Patcher.exe [path/file]")
	}

	filename := os.Args[1]

	f, err := os.Open(filename)
	if err != nil {
		log.Fatalln("[!] Selected File not found!")
	}
	defer f.Close()

	//Parse PE File
	PEParser(f)

}
