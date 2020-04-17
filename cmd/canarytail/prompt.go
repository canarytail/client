package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
)

type Prompt struct {
	scanner *bufio.Scanner
}

func NewStdinPrompt() *Prompt {
	return &Prompt{scanner: bufio.NewScanner(os.Stdin)}
}

func (p *Prompt) Input(question string) (string, error) {
	fmt.Printf("%s: ", question)

	p.scanner.Scan()
	response := p.scanner.Text()
	if err := p.scanner.Err(); err != nil {
		return "", &ConsoleError{Message: "unexpected program error", Err: err}
	}

	return response, nil
}

func (p *Prompt) InputWithOptions(question string, options []string, defaultOpt string) (string, error) {
	if len(options) == 0 {
		return "", errors.New("options should not be empty")
	}

	fmt.Printf("%s (", question)
	for i, opt := range options {
		fmt.Print(opt)
		if i != len(options)-1 {
			fmt.Print("/")
		} else {
			fmt.Print("): ")
		}
	}

	p.scanner.Scan()
	response := p.scanner.Text()
	if err := p.scanner.Err(); err != nil {
		return "", &ConsoleError{Message: "unexpected program error", Err: err}
	}

	// user didn't enter anythin, use default option
	if response == "" {
		return defaultOpt, nil
	}

	// check if user entered correct option
	selected, found := IgnoreCaseContains(response, options)
	if !found {
		return "", &ConsoleError{Message: "invalid option entered"}
	}

	return selected, nil
}

func IgnoreCaseContains(target string, options []string) (string, bool) {
	target = strings.ToLower(target)
	for _, opt := range options {
		if strings.ToLower(opt) == target {
			return opt, true
		}
	}
	return "", false
}
