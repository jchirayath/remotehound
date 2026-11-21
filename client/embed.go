// Package client embeds the device bootstrap scripts so the server binary is
// self-contained. The scripts are templates with exactly two placeholders,
// __RH_BASE_URL__ and __RH_CODE__, replaced by internal/enroll.
package client

import _ "embed"

// BootstrapSH is the POSIX sh bootstrap for Linux and macOS.
//
//go:embed bootstrap.sh
var BootstrapSH string

// BootstrapPS1 is the PowerShell bootstrap for Windows.
//
//go:embed bootstrap.ps1
var BootstrapPS1 string
