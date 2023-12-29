package main

import (
	"encoding/binary"
	"log"
	"syscall"
	"test/pkg/windows"
	"unsafe"
)

func main() {
	size := unsafe.Sizeof(pkg.CONTEXT{})
	log.Printf("CONTEXT struct size %d bytes\n", size)
	srcPath := "c:\\\\windows\\\\system32\\\\calc.exe"
	cmd, err := syscall.UTF16PtrFromString(srcPath)
	if err != nil {
		panic(err)
	}

	log.Printf("Creating process: %v\n", srcPath)

	si := new(syscall.StartupInfo)
	pi := new(syscall.ProcessInformation)
	defer syscall.CloseHandle(pi.Thread)
	defer syscall.CloseHandle(pi.Process)

	// CREATE_SUSPENDED := 0x00000004
	err = syscall.CreateProcess(cmd, nil, nil, nil, false, 0x00000004, nil, nil, si, pi)
	if err != nil {
		panic(err)
	}

	hProcess := uintptr(pi.Process)
	hThread := uintptr(pi.Thread)
	dwProcessId := pi.ProcessId
	dwThreadId := pi.ThreadId
	log.Printf("Process created:\n")
	log.Printf("hProcess: %v, hThread: %v", hProcess, hThread)
	log.Printf("dwProcessID: %v, dwThreadID: %v", dwProcessId, dwThreadId)

	log.Printf("-------------------Method1--------------------------------")
	ctx, err := pkg.GetThreadContext(hThread)
	if err != nil {
		panic(err)
	}
	// https://stackoverflow.com/questions/37656523/declaring-context-struct-for-pinvoke-windows-x64
	Rdx := binary.LittleEndian.Uint64(ctx[136:])

	log.Printf("ctx Address to PEB[Rdx]: %x-%d\n", Rdx, Rdx)

	log.Printf("-------------------Method2--------------------------------")
	ctx2, err := pkg.GetThreadContext2(hThread)
	if err != nil {
		panic(err)
	}

	log.Printf("ctx2 Address to PEB [Rdx]: %x-%d\n", ctx2.Rdx, ctx2.Rdx)

}
