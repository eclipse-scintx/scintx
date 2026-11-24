// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package main

import (
	"fmt"
	"os"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		if err := runServe(); err != nil {
			fmt.Fprintf(os.Stderr, "serve failed: %v\n", err)
			os.Exit(1)
		}
		return
	}
	switch args[0] {
	case "serve":
		if err := runServe(); err != nil {
			fmt.Fprintf(os.Stderr, "serve failed: %v\n", err)
			os.Exit(1)
		}
	case "health":
		if err := runHealth(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "health probe failed: %v\n", err)
			os.Exit(1)
		}
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", args[0])
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage:
  scintx              Start the Eclipse SCINTX HTTP gateway (same as: scintx serve)
  scintx serve        Start the Eclipse SCINTX HTTP gateway
  scintx health       Probe gateway readiness (/readyz) for container healthchecks
  scintx help         Show this help
`)
}
