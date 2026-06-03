//go:build !windows

package sysmon

import "time"

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

func Collect(_ time.Time) SysmonState { return SysmonState{Available: false} }
