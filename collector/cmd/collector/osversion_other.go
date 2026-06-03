//go:build !windows && !darwin

package main

import "runtime"

func osVersion() string { return runtime.GOOS }
