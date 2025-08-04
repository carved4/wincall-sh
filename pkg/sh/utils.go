package sh

import (
	"fmt"
	"unsafe"
	api "github.com/carved4/go-wincall"
)	

func GetCurrentThreadHandle() (uintptr, error) {
	handle, err := api.Call("kernel32.dll", "GetCurrentThread")
	if err != nil {
		return 0, fmt.Errorf("GetCurrentThread failed: %v", err)
	}
	return handle, nil
}

func OpenThreadById(threadId uint32) (uintptr, error) {
	const THREAD_SET_CONTEXT = 0x0010
	
	handle, err := api.Call("kernel32.dll", "OpenThread",
		uintptr(THREAD_SET_CONTEXT), // dwDesiredAccess
		uintptr(0),                  // bInheritHandle (FALSE)
		uintptr(threadId),           // dwThreadId
	)
	if err != nil || handle == 0 {
		return 0, fmt.Errorf("OpenThread failed for TID %d: %v", threadId, err)
	}
	return handle, nil
}

func AllocateReserveObject() (uintptr, error) {
	var reserveHandle uintptr
	
	success, err := api.Call("ntdll.dll", "NtAllocateReserveObject",
		uintptr(unsafe.Pointer(&reserveHandle)), // ObjectHandle
		uintptr(0),                              // ObjectAttributes (NULL)
		uintptr(1),                              // ObjectType (1 = UserApcReserve)
	)
	if err != nil || success != 0 {
		return 0, fmt.Errorf("NtAllocateReserveObject failed: %v (status: 0x%x)", err, success)
	}
	
	return reserveHandle, nil
}

func CloseHandle(handle uintptr) error {
	success, err := api.Call("kernel32.dll", "CloseHandle", handle)
	if err != nil || success == 0 {
		return fmt.Errorf("CloseHandle failed: %v", err)
	}
	return nil
}

func ExecuteInCurrentThread() error {
	threadHandle, err := GetCurrentThreadHandle()
	if err != nil {
		return fmt.Errorf("failed to get current thread handle: %v", err)
	}
	
	return Execute(threadHandle)
}

func ExecuteInThreadById(threadId uint32) error {
	threadHandle, err := OpenThreadById(threadId)
	if err != nil {
		return fmt.Errorf("failed to open thread %d: %v", threadId, err)
	}
	defer CloseHandle(threadHandle)
	
	return Execute(threadHandle)
}