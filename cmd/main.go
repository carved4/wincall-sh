package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"shellcode/pkg/sh"
	"strconv"
	"strings"
)

type ExecutionMethod struct {
	Name        string
	Description string
	Execute     func() error
}

var methods = []ExecutionMethod{
	{
		Name:        "waitobj",
		Description: "Execute via Wait Object",
		Execute: func() error {
			err := sh.ExecuteViaWaitObject()
			if err != nil {
				log.Println("[-] waitobj setup failed:", err)
				return err
			}
			log.Println("[+] waitobj setup successful")
			return nil
		},
	},
	{
		Name:        "settimer",
		Description: "Execute via SetTimer",
		Execute: func() error {
			err := sh.ExecuteViaSetTimer()
			if err != nil {
				log.Println("[-] settimer setup failed:", err)
				return err
			}
			log.Println("[+] settimer setup successful")
			return nil
		},
	},
	{
		Name:        "drawstate",
		Description: "Execute via DrawState",
		Execute: func() error {
			err := sh.ExecuteViaDrawState()
			if err != nil {
				log.Println("[-] drawstate setup failed:", err)
				return err
			}
			log.Println("[+] drawstate setup successful")
			return nil
		},
	},
	{
		Name:        "graystring",
		Description: "Execute via GrayString",
		Execute: func() error {
			err := sh.ExecuteViaGrayString()
			if err != nil {
				log.Println("[-] gray string setup failed:", err)
				return err
			}
			log.Println("[+] gray string registered successfully")
			return nil
		},
	},
	{
		Name:        "enclave",
		Description: "Execute via Enclave",
		Execute: func() error {
			err := sh.ExecuteEnclave()
			if err != nil {
				log.Println("[-] enclave setup failed:", err)
				return err
			}
			log.Println("[+] enclave execution completed")
			return nil
		},
	},
	{
		Name:        "timerqueue",
		Description: "Execute via Timer Queue",
		Execute: func() error {
			err := sh.ExecuteViaTimerQueue()
			if err != nil {
				log.Println("[-] targeted DLL notification setup failed:", err)
				return err
			}
			log.Println("[+] targeted DLL notification callback registered successfully")
			return nil
		},
	},
	{
		Name:        "audio",
		Description: "Execute via Audio Callback",
		Execute: func() error {
			err := sh.ExecuteViaAudioCallback()
			if err != nil {
				log.Println("[-] audio callback setup failed:", err)
				return err
			}
			log.Println("[+] audio callback registered successfully")
			defer sh.CloseAudioDevice()

			err = sh.TriggerAudioEvent()
			if err != nil {
				log.Println("[-] audio trigger failed:", err)
				return err
			}
			log.Println("[+] audio event triggered successfully")
			return nil
		},
	},
	{
		Name:        "mci",
		Description: "Execute via MCI Yield",
		Execute: func() error {
			err := sh.ExecuteViaMCIYield()
			if err != nil {
				log.Println("[-] MCI yield setup failed:", err)
				return err
			}
			log.Println("[+] MCI yield procedure set successfully")
			return nil
		},
	},
	{
		Name:        "keyboard",
		Description: "Execute via Keyboard Hook",
		Execute: func() error {
			err := sh.ExecuteViaKeyboardHook()
			if err != nil {
				log.Println("[-] keyboard hook setup failed:", err)
				return err
			}
			log.Println("[+] keyboard hook registered successfully")
			return nil
		},
	},
}


func showMenu() {
	fmt.Println("\n[+] available execution methods:")
	for i, method := range methods {
		fmt.Printf("%2d. %s - %s\n", i+1, method.Name, method.Description)
	}
	fmt.Println()
}

func getUserChoice() (int, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Select method (1-" + strconv.Itoa(len(methods)) + "): ")
	input, err := reader.ReadString('\n')
	if err != nil {
		return 0, err
	}

	input = strings.TrimSpace(input)
	choice, err := strconv.Atoi(input)
	if err != nil {
		return 0, fmt.Errorf("invalid input: must be a number")
	}

	if choice < 1 || choice > len(methods) {
		return 0, fmt.Errorf("choice out of range: must be between 1 and %d", len(methods))
	}

	return choice - 1, nil
}

func findMethodByName(name string) *ExecutionMethod {
	name = strings.ToLower(name)
	for i := range methods {
		if strings.ToLower(methods[i].Name) == name {
			return &methods[i]
		}
	}
	return nil
}

func main() {
	debug.SetGCPercent(-1)

	methodFlag := flag.String("method", "", "Execution method to use (waitobj, settimer, drawstate, graystring, enclave, timerqueue, audio, mci, keyboard, all)")
	listFlag := flag.Bool("list", false, "List available methods")
	flag.Parse()

	if *listFlag {
		showMenu()
		return
	}

	if *methodFlag != "" {
		method := findMethodByName(*methodFlag)
		if method == nil {
			log.Fatalf("Unknown method: %s\nUse --list to see available methods", *methodFlag)
		}
		
		log.Printf("[+] executing method: %s", method.Description)
		if err := method.Execute(); err != nil {
			log.Fatalf("Execution failed: %v", err)
		}
		return
	}

	fmt.Println("[+] shellcode execution tool")

	for {
		showMenu()
		choice, err := getUserChoice()
		if err != nil {
			fmt.Printf("Error: %v\n\n", err)
			continue
		}

		method := methods[choice]
		log.Printf("[+] executing method: %s", method.Description)
		if err := method.Execute(); err != nil {
			log.Printf("Execution failed: %v", err)
		}

		fmt.Print("\nRun another method? (y/N): ")
		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToLower(response))
		if response != "y" && response != "yes" {
			break
		}
	}

	fmt.Println("Goodbye!")
}