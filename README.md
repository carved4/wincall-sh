# wincall-sh

## overview

this project demonstrates creative shellcode execution techniques using the go-wincall API :3 x64 only

## purpose

this is a research and educational tool designed to show the capabilities of the go-wincall API in shellcode operations. it explores obscure windows APIs and callback mechanisms that can be used for shellcode execution.

## execution methods
>all use the x64 winexec calc shellcode stored in hex format in get.go
### timer queue callback
- `ExecuteViaTimerQueue()` - uses `CreateTimerQueueTimer` to register shellcode as a timer callback
- `DeleteTimer()` - cleans up timer queue timer

### keyboard hook callback  
- `ExecuteViaKeyboardHook()` - uses `SetWindowsHookExW` with low-level keyboard hook
- `SimulateKeypress()` - simulates spacebar press to trigger shellcode
- `UnhookKeyboard()` - removes the keyboard hook

### audio device callback
- `ExecuteViaAudioCallback()` - uses `waveOutOpen` with shellcode as callback
- `ExecuteViaAudioInput()` - uses `waveInOpen` with shellcode as callback  
- `ExecuteViaMCIYield()` - uses `mciSetYieldProc` with shellcode as yield procedure
- `TriggerAudioEvent()` - starts audio device to trigger callbacks
- `CloseAudioDevice()` - closes the audio device

### draw state callback
- `ExecuteViaDrawState()` - uses `DrawStateA` with `DST_COMPLEX` flag
- `createSimpleWindow()` - creates window for device context
- `destroyWindow()` - cleans up window

### wait object callback
- `ExecuteViaWaitObject()` - uses `RegisterWaitForSingleObject` 
- `cleanupWaitObject()` - cleans up wait object and event

### set timer callback
- `ExecuteViaSetTimer()` - uses `SetTimer` with shellcode as `TIMERPROC`
- `createMessageWindow()` - creates message-only window for timer
- `processMessages()` - processes window messages to trigger timer
- `destroyMessageWindow()` - cleans up message window

### gray string callback
- `ExecuteViaGrayString()` - uses `GrayStringA` for disabled text rendering
- `createSimpleWindow()` - creates window for device context
- `destroyWindow()` - cleans up window

### enclave callback
- `ExecuteEnclave()` - uses `LdrCallEnclave` to execute shellcode in enclave context

### apc callback
- `Execute()` - uses `NtQueueApcThreadEx2` to queue shellcode as APC routine
- `ExecuteWithReserve()` - uses `NtQueueApcThreadEx2` with reserve handle


## usage

```bash
# build the project
go build -o wincallsh.exe cmd/main.go

# run with different execution methods
./wincallsh.exe
```

## technical details

- all methods use `VirtualProtect` to make shellcode executable
- shellcode is passed directly as callback function pointers
- no traditional process injection techniques used
- leverages legitimate windows API callback mechanisms
- demonstrates creative use of go-wincall for shellcode operations

