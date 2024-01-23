package main

import (
	"fmt"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

//Windows amd64

const (
	IMAGE_DOS_SIGNATURE = 0x5A4D
	IMAGE_NT_SIGNATURE  = 0x00004550
)

const (
	CREATE_SUSPENDED                = 0x00000004
	PROCESS_BASIC_INFORMATION_CLASS = 0
)

var (
	ntdll             = windows.NewLazySystemDLL("ntdll.dll")
	ntQueryInfoProc   = ntdll.NewProc("NtQueryInformationProcess")
	ntReadVirtualProc = ntdll.NewProc("NtReadVirtualMemory")
)

type ProcessBasicInformation struct {
	Reserved1       uintptr
	PebBaseAddress  uintptr
	Reserved2       [2]uintptr
	UniqueProcessId uintptr
	Reserved3       uintptr
}

type ImageDosHeader struct {
	e_magic    uint16
	e_cblp     uint16
	e_cp       uint16
	e_crlc     uint16
	e_cparhdr  uint16
	e_minalloc uint16
	e_maxalloc uint16
	e_ss       uint16
	e_sp       uint16
	e_csum     uint16
	e_ip       uint16
	e_cs       uint16
	e_lfarlc   uint16
	e_ovno     uint16
	e_res      [4]uint16
	e_oemid    uint16
	e_oeminfo  uint16
	e_res2     [10]uint16
	e_lfanew   int32
}

type ImageNtHeaders64 struct {
	Signature      uint32
	FileHeader     ImageFileHeader
	OptionalHeader ImageOptionalHeader64
}

type ImageFileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type ImageOptionalHeader64 struct {
	Magic                       uint16
	MajorLinkerVersion          byte
	MinorLinkerVersion          byte
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
	DataDirectory               [16]ImageDataDirectory
}

type ImageDataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

func main() {

	srcPath := "c:\\\\windows\\\\system32\\\\svchost.exe"
	cmd, err := syscall.UTF16PtrFromString(srcPath)
	if err != nil {
		panic(err)
	}

	fmt.Printf("[+] Running EXE File: %v\n", srcPath)

	si := new(syscall.StartupInfo)
	pi := new(syscall.ProcessInformation)
	defer syscall.CloseHandle(pi.Thread)
	defer syscall.CloseHandle(pi.Process)

	// CREATE_SUSPENDED := 0x00000004
	err = syscall.CreateProcess(cmd, nil, nil, nil, false, CREATE_SUSPENDED, nil, nil, si, pi)
	if err != nil {
		panic(err)
	}

	hProcess := uintptr(pi.Process)
	hThread := uintptr(pi.Thread)
	dwProcessId := pi.ProcessId
	dwThreadId := pi.ThreadId
	fmt.Printf("[+] Process created.\n")
	fmt.Printf("[+] hProcess: %v, hThread: %v\n", hProcess, hThread)
	fmt.Printf("[+] dwProcessID: %v, dwThreadID: %v\n", dwProcessId, dwThreadId)

	var pbi ProcessBasicInformation

	// call NtQueryInformationProcess()
	ret, err := ntQueryInformationProcess(pi.Process, PROCESS_BASIC_INFORMATION_CLASS, uintptr(unsafe.Pointer(&pbi)), uint32(unsafe.Sizeof(pbi)), nil)
	if ret != 0 {
		fmt.Println("[-] Error calling NtQueryInformationProcess:", err)
		return
	}

	fmt.Printf("[+] Unique Process ID: %v\n", pbi.UniqueProcessId)
	fmt.Printf("[+] PEB Base Address: 0x%X\n", pbi.PebBaseAddress)

	imageBaseOffset := pbi.PebBaseAddress + 0x10
	var imageBaseBuffer [unsafe.Sizeof(uintptr(0))]byte
	var bytesRead uintptr
	//bufferSize := 1024
	//	image_base_buffer := make([]byte, bufferSize)

	status, err := ntReadVirtualMemory(pi.Process, imageBaseOffset, uintptr(unsafe.Pointer(&imageBaseBuffer[0])), uintptr(len(imageBaseBuffer)), &bytesRead)
	if status != 0 {
		fmt.Println("[-] Error calling NtReadVirtualMemory:", err)
		return
	}
	imageBaseAddress := *(*uintptr)(unsafe.Pointer(&imageBaseBuffer[0]))

	fmt.Printf("[+] ImageBaseAddr: %#x\n", imageBaseAddress)

	var imageDosHeader ImageDosHeader

	status2, err := ntReadVirtualMemory(pi.Process, imageBaseAddress, uintptr(unsafe.Pointer(&imageDosHeader)), unsafe.Sizeof(imageDosHeader), &bytesRead)
	if status2 != 0 {
		fmt.Println("[-] Error calling NtReadVirtualMemory:", err)
		return
	}

	if imageDosHeader.e_magic != IMAGE_DOS_SIGNATURE {
		fmt.Println("[-] Error: IMAGE_DOS_HEADER is invalid")
	}
	fmt.Printf("[+] e_magic: %#x\n", imageDosHeader.e_magic)
	fmt.Printf("[+] e_lfanew: %#x\n", imageDosHeader.e_lfanew)

	var imageNtHeader ImageNtHeaders64
	//var image_optional_header64 ImageOptionalHeader64
	ntHeaderOffset := imageBaseAddress + uintptr(imageDosHeader.e_lfanew)

	status3, err := ntReadVirtualMemory(pi.Process, ntHeaderOffset, uintptr(unsafe.Pointer(&imageNtHeader)), unsafe.Sizeof(imageNtHeader), &bytesRead)
	if status3 != 0 {
		fmt.Println("[-] Error calling NtReadVirtualMemory:", err)
		return
	}

	if imageNtHeader.Signature != IMAGE_NT_SIGNATURE {
		fmt.Println("[-] Error: IMAGE_NT_HEADER is invalid")
	}
	sizeOfOptionalHeader := imageNtHeader.FileHeader.SizeOfOptionalHeader
	fmt.Printf("[+] SizeOfOptionalHeader: %#x\n", sizeOfOptionalHeader)
	fmt.Printf("[+] Image_nt_header.Signature: %#x\n", imageNtHeader.Signature)
	addressOfEntryPoint := uintptr(imageNtHeader.OptionalHeader.AddressOfEntryPoint)
	entrypoint := imageBaseAddress + addressOfEntryPoint
	fmt.Printf("[+] AddressOfEntryPoint: %#x\n", addressOfEntryPoint)
	fmt.Printf("[+] Entry Point: %#x\n", entrypoint)

}

func ntQueryInformationProcess(processHandle syscall.Handle, processInformationClass uint32, processInformation uintptr, processInformationLength uint32, returnLength *uint32) (uintptr, error) {
	ret, _, err := ntQueryInfoProc.Call(
		uintptr(processHandle),
		uintptr(processInformationClass),
		processInformation,
		uintptr(processInformationLength),
		uintptr(unsafe.Pointer(returnLength)),
	)
	if ret != 0 {
		return 0, err
	}
	return ret, nil
}

func ntReadVirtualMemory(processHandle syscall.Handle, baseAddress uintptr, buffer uintptr, size uintptr, bytesRead *uintptr) (uintptr, error) {
	ret, _, err := ntReadVirtualProc.Call(
		uintptr(processHandle),
		baseAddress,
		buffer,
		size,
		uintptr(unsafe.Pointer(bytesRead)),
	)
	if ret != 0 {
		return 0, err
	}
	return ret, nil
}
