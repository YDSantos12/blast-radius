//go:build windows

package main

import "golang.org/x/sys/windows/registry"

func osVersion() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.READ)
	if err != nil {
		return "windows"
	}
	defer k.Close()

	name, _, _ := k.GetStringValue("ProductName")
	dv, _, _ := k.GetStringValue("DisplayVersion")
	build, _, _ := k.GetStringValue("CurrentBuildNumber")

	if name == "" {
		return "windows"
	}
	if dv != "" {
		return name + " " + dv + " (build " + build + ")"
	}
	return name + " (build " + build + ")"
}
