package pkg

import (
	"encoding/binary"
	"syscall"
	"unsafe"
)

const (
	CONTEXT_FULL      = 0x10007
	THREAD_ALL_ACCESS = 0x1F03FF
	MEM_COMMIT        = 0x00001000
	MEM_RELEASE       = 0x8000
	MEM_RESERVE       = 0x00002000
	PAGE_READWRITE    = 0x40
	CREATE_SUSPENDED  = 0x00000004
	CONTEXT_INTEGER   = (0x000100000 | 0x000000002)
)

type M128A struct {
	Low  uint64
	High int64
}

type XMM_SAVE_AREA32 struct {
	Control        uint32
	Status         uint32
	Tag            uint32
	Reserved1      uint32
	ErrorOffset    uint32
	ErrorSelector  uint32
	Reserved2      uint32
	DataOffset     uint32
	DataSelector   uint32
	Reserved3      uint32
	MxCsr          uint32
	MxCsr_Mask     uint32
	FloatRegisters [8]M128A
	XmmRegisters   [16]M128A
	Reserved4      [96]byte
}

// https://stackoverflow.com/questions/37656523/declaring-context-struct-for-pinvoke-windows-x64
type CONTEXT struct {
	P1Home               uint64
	P2Home               uint64
	P3Home               uint64
	P4Home               uint64
	P5Home               uint64
	P6Home               uint64
	ContextFlags         uint32
	MxCsr                uint32
	SegCs                uint16
	SegDs                uint16
	SegEs                uint16
	SegFs                uint16
	SegGs                uint16
	SegSs                uint16
	EFlags               uint32
	Dr0                  uint64
	Dr1                  uint64
	Dr2                  uint64
	Dr3                  uint64
	Dr6                  uint64
	Dr7                  uint64
	Rax                  uint64
	Rcx                  uint64
	Rdx                  uint64
	Rbx                  uint64
	Rsp                  uint64
	Rbp                  uint64
	Rsi                  uint64
	Rdi                  uint64
	R8                   uint64
	R9                   uint64
	R10                  uint64
	R11                  uint64
	R12                  uint64
	R13                  uint64
	R14                  uint64
	R15                  uint64
	Rip                  uint64
	FltSave              XMM_SAVE_AREA32
	Header               M128A
	Legacy               [2]M128A
	Xmm0                 M128A
	Xmm1                 M128A
	Xmm2                 M128A
	Xmm3                 M128A
	Xmm4                 M128A
	Xmm5                 M128A
	Xmm6                 M128A
	Xmm7                 M128A
	Xmm8                 M128A
	Xmm9                 M128A
	Xmm10                M128A
	Xmm11                M128A
	Xmm12                M128A
	Xmm13                M128A
	Xmm14                M128A
	Xmm15                M128A
	VectorRegister       [26]M128A
	VectorControl        uint64
	DebugControl         uint64
	LastBranchToRip      uint64
	LastBranchFromRip    uint64
	LastExceptionToRip   uint64
	LastExceptionFromRip uint64
}

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	ntdll    = syscall.NewLazyDLL("ntdll.dll")

	procOpenThread       = kernel32.NewProc("OpenThread")
	procGetThreadContext = kernel32.NewProc("GetThreadContext")
	procVirtualAlloc     = kernel32.NewProc("VirtualAlloc")
	procVirtualFree      = kernel32.NewProc("VirtualFree")
	pVirtualAllocEx      = kernel32.NewProc("VirtualAllocEx")

	pNtResumeThread         = ntdll.NewProc("NtResumeThread")
	pNtGetContextThread     = ntdll.NewProc("NtGetContextThread")
	pNtSetContextThread     = ntdll.NewProc("NtSetContextThread")
	pNtReadVirtualMemory    = ntdll.NewProc("NtReadVirtualMemory")
	pNtUnmapViewOfSection   = ntdll.NewProc("NtUnmapViewOfSection")
	pNtWriteVirtualMemory   = ntdll.NewProc("NtWriteVirtualMemory")
	pNtProtectVirtualMemory = ntdll.NewProc("NtProtectVirtualMemory")
)

func OpenThread(threadID uint32) (syscall.Handle, error) {
	handle, _, err := procOpenThread.Call(THREAD_ALL_ACCESS, 0, uintptr(threadID))
	if handle == 0 {
		return 0, err
	}
	return syscall.Handle(handle), nil
}

func VirtualAlloc(size uintptr) (uintptr, error) {
	addr, _, err := procVirtualAlloc.Call(0, size, MEM_COMMIT, PAGE_READWRITE)
	if addr == 0 {
		return 0, err
	}
	return addr, nil
}

func VirtualFree(addr uintptr) error {
	_, _, err := procVirtualFree.Call(addr, 0, MEM_RELEASE)
	if err != nil {
		return err
	}
	return nil
}

// Method1:GetThreadContext func() to get Thread Context
func GetThreadContext(hThread uintptr) (ctx []uint8, e error) {

	// BOOL GetThreadContext(
	// 	HANDLE    hThread,
	// 	LPCONTEXT lpContext
	// );

	ctx = make([]uint8, 1232)

	// ctx[12] = 0x00100000 | 0x00000002 //CONTEXT_INTEGER flag to Rdx
	binary.LittleEndian.PutUint32(ctx[48:], CONTEXT_INTEGER)
	//other offsets can be found  at https://stackoverflow.com/questions/37656523/declaring-context-struct-for-pinvoke-windows-x64
	ctxPtr := unsafe.Pointer(&ctx[0])
	r, _, err := procGetThreadContext.Call(hThread, uintptr(ctxPtr))
	if r == 0 {
		e = err
	}
	//log.Printf("GetThreadContext[%v]: [%v] %v\n", hThread, r, err)

	return ctx, nil
}

// Method2:GetThreadContext func() to get Thread Context
func GetThreadContext2(hThread uintptr) (ctx CONTEXT, e error) {

	ctx.ContextFlags = CONTEXT_INTEGER
	//pNtGetContextThreadResult, _, _ := pNtGetContextThread.Call(hThread, uintptr(unsafe.Pointer(&ctx)))
	_, _, _ = pNtGetContextThread.Call(
		hThread, uintptr(unsafe.Pointer(&ctx)))

	return ctx, nil
}
