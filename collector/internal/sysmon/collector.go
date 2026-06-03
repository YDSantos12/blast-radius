//go:build windows

package sysmon

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type SysmonState struct {
	Available bool          `json:"sysmon_available"`
	Events    []SysmonEvent `json:"events"`
}

type SysmonEvent struct {
	EventID  int               `json:"event_id"`
	TimeUTC  string            `json:"time_utc"`
	Computer string            `json:"computer"`
	Fields   map[string]string `json:"fields"`
}

const (
	evtQueryChannelPath = 0x1
	evtRenderEventXml   = 1
	maxEvents           = 1000
)

var (
	modWevtapi   = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery  = modWevtapi.NewProc("EvtQuery")
	procEvtNext   = modWevtapi.NewProc("EvtNext")
	procEvtRender = modWevtapi.NewProc("EvtRender")
	procEvtClose  = modWevtapi.NewProc("EvtClose")
)

// Collect reads Sysmon events from the Windows Event Log.
// If incidentWindowStart is zero, events from the last 24 hours are used.
// Returns Available=false if Sysmon is not installed or the log is inaccessible.
func Collect(incidentWindowStart time.Time) SysmonState {
	since := incidentWindowStart
	if since.IsZero() {
		since = time.Now().UTC().Add(-24 * time.Hour)
	}

	events, err := querySysmon(since)
	if err != nil {
		fmt.Fprintf(os.Stderr, "blast-radius: sysmon: %v\n", err)
		return SysmonState{Available: false}
	}
	return SysmonState{Available: true, Events: events}
}

func querySysmon(since time.Time) ([]SysmonEvent, error) {
	if err := modWevtapi.Load(); err != nil {
		return nil, fmt.Errorf("wevtapi.dll unavailable: %w", err)
	}

	xpathQuery := fmt.Sprintf(
		"*[System[Provider[@Name='Microsoft-Windows-Sysmon']"+
			" and (EventID=1 or EventID=3 or EventID=11 or EventID=13)"+
			" and TimeCreated[@SystemTime>='%s']]]",
		since.UTC().Format("2006-01-02T15:04:05.000")+"Z",
	)

	channelPtr, err := windows.UTF16PtrFromString("Microsoft-Windows-Sysmon/Operational")
	if err != nil {
		return nil, err
	}
	queryPtr, err := windows.UTF16PtrFromString(xpathQuery)
	if err != nil {
		return nil, err
	}

	r0, _, e := procEvtQuery.Call(
		0,
		uintptr(unsafe.Pointer(channelPtr)),
		uintptr(unsafe.Pointer(queryPtr)),
		evtQueryChannelPath,
	)
	if r0 == 0 {
		return nil, fmt.Errorf("EvtQuery: %w", e)
	}
	resultSet := windows.Handle(r0)
	defer procEvtClose.Call(uintptr(resultSet))

	batch := make([]windows.Handle, 10)
	var events []SysmonEvent

	for len(events) < maxEvents {
		n, err := evtNextBatch(resultSet, batch)
		if err != nil {
			return nil, fmt.Errorf("EvtNext: %w", err)
		}
		if n == 0 {
			break
		}
		for i := 0; i < n; i++ {
			raw, err := renderEvent(batch[i])
			procEvtClose.Call(uintptr(batch[i]))
			if err != nil {
				continue
			}
			if ev := filterEvent(raw); ev != nil {
				events = append(events, *ev)
			}
		}
	}
	return events, nil
}

func evtNextBatch(resultSet windows.Handle, batch []windows.Handle) (int, error) {
	var returned uint32
	r0, _, e := procEvtNext.Call(
		uintptr(resultSet),
		uintptr(len(batch)),
		uintptr(unsafe.Pointer(&batch[0])),
		500, // ms timeout
		0,   // reserved
		uintptr(unsafe.Pointer(&returned)),
	)
	if r0 == 0 {
		if errno, ok := e.(syscall.Errno); ok && errno == 259 { // ERROR_NO_MORE_ITEMS
			return 0, nil
		}
		return 0, e
	}
	return int(returned), nil
}

func renderEvent(event windows.Handle) (*rawEventXML, error) {
	var used, count uint32
	// First call with zero buffer to get required size; expects ERROR_INSUFFICIENT_BUFFER.
	procEvtRender.Call(0, uintptr(event), evtRenderEventXml, 0, 0,
		uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&count)))
	if used == 0 {
		return nil, fmt.Errorf("EvtRender: zero buffer size")
	}

	buf := make([]uint16, (used+1)/2)
	r0, _, e := procEvtRender.Call(
		0, uintptr(event), evtRenderEventXml,
		uintptr(used), uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&count)),
	)
	if r0 == 0 {
		return nil, e
	}

	var ev rawEventXML
	if err := xml.Unmarshal([]byte(windows.UTF16ToString(buf)), &ev); err != nil {
		return nil, err
	}
	return &ev, nil
}

type rawEventXML struct {
	System struct {
		EventID     int    `xml:"EventID"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Computer string `xml:"Computer"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

// filterEvent applies post-query field-level filters and returns a SysmonEvent
// if the event is relevant to the collection goals, or nil to drop it.
func filterEvent(raw *rawEventXML) *SysmonEvent {
	fields := make(map[string]string, len(raw.EventData.Data))
	for _, d := range raw.EventData.Data {
		fields[d.Name] = d.Value
	}

	id := raw.System.EventID
	switch id {
	case 1: // Process Create: child of Code.exe or node.exe (npm)
		parent := strings.ToLower(filepath.Base(fields["ParentImage"]))
		if parent != "code.exe" && parent != "node.exe" {
			return nil
		}
		child := strings.ToLower(filepath.Base(fields["Image"]))
		switch child {
		case "node.exe", "python.exe", "powershell.exe", "cmd.exe":
		default:
			return nil
		}
		return buildEvent(id, raw, fields,
			"Image", "CommandLine", "ParentImage", "ParentCommandLine", "User")

	case 3: // Network Connection: outbound from monitored processes
		if fields["Initiated"] != "true" {
			return nil
		}
		proc := strings.ToLower(filepath.Base(fields["Image"]))
		switch proc {
		case "node.exe", "python.exe", "code.exe":
		default:
			return nil
		}
		return buildEvent(id, raw, fields,
			"Image", "DestinationIp", "DestinationPort", "DestinationHostname")

	case 11: // File Create: in credential locations
		if !isCredentialPath(strings.ToLower(fields["TargetFilename"])) {
			return nil
		}
		return buildEvent(id, raw, fields, "Image", "TargetFilename", "CreationUtcTime")

	case 13: // Registry Value Set: Run key writes
		if !strings.Contains(strings.ToLower(fields["TargetObject"]), `currentversion\run`) {
			return nil
		}
		return buildEvent(id, raw, fields, "Image", "TargetObject", "Details")
	}
	return nil
}

func buildEvent(id int, raw *rawEventXML, all map[string]string, keep ...string) *SysmonEvent {
	ev := &SysmonEvent{
		EventID:  id,
		TimeUTC:  raw.System.TimeCreated.SystemTime,
		Computer: raw.System.Computer,
		Fields:   make(map[string]string, len(keep)),
	}
	for _, k := range keep {
		if v, ok := all[k]; ok {
			ev.Fields[k] = v
		}
	}
	return ev
}

func isCredentialPath(lower string) bool {
	for _, marker := range []string{
		".npmrc", ".git-credentials", ".aws", ".ssh", ".azure", ".pypirc", ".docker",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
