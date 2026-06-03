//go:build windows

package system

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

type SystemState struct {
	RegistryRunKeys []RegistryRunKey `json:"registry_run_keys"`
	ScheduledTasks  []ScheduledTask  `json:"scheduled_tasks"`
}

type RegistryRunKey struct {
	Hive  string `json:"hive"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

type ScheduledTask struct {
	TaskName  string `json:"task_name"`
	TaskToRun string `json:"task_to_run"`
	Author    string `json:"author"`
	RunAsUser string `json:"run_as_user"`
	Status    string `json:"status"`
}

func Collect() SystemState {
	return SystemState{
		RegistryRunKeys: collectRunKeys(),
		ScheduledTasks:  collectScheduledTasks(),
	}
}

var runKeyPaths = []struct {
	hive string
	root registry.Key
	path string
}{
	{"HKCU", registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`},
	{"HKLM", registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`},
}

func collectRunKeys() []RegistryRunKey {
	var items []RegistryRunKey
	for _, rk := range runKeyPaths {
		k, err := registry.OpenKey(rk.root, rk.path, registry.READ)
		if err != nil {
			continue
		}
		names, err := k.ReadValueNames(-1)
		if err != nil {
			k.Close()
			continue
		}
		for _, name := range names {
			val, _, err := k.GetStringValue(name)
			if err != nil {
				continue
			}
			items = append(items, RegistryRunKey{
				Hive:  rk.hive,
				Name:  name,
				Value: val,
			})
		}
		k.Close()
	}
	return items
}

func collectScheduledTasks() []ScheduledTask {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "schtasks", "/query", "/fo", "CSV", "/v").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "blast-radius: schtasks: %v\n", err)
		return nil
	}

	// Strip UTF-8 BOM if present — schtasks emits one on some locales.
	data := bytes.TrimPrefix(out, []byte{0xef, 0xbb, 0xbf})

	r := csv.NewReader(bufio.NewReader(bytes.NewReader(data)))
	r.LazyQuotes = true
	rows, err := r.ReadAll()
	if err != nil || len(rows) < 2 {
		return nil
	}

	header := rows[0]
	col := func(name string) int {
		for i, h := range header {
			if strings.EqualFold(strings.TrimSpace(h), name) {
				return i
			}
		}
		return -1
	}
	safe := func(row []string, idx int) string {
		if idx < 0 || idx >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[idx])
	}

	idxName   := col("TaskName")
	idxRun    := col("Task To Run")
	idxAuthor := col("Author")
	idxRunAs  := col("Run As User")
	idxStatus := col("Status")

	if idxName < 0 {
		return nil
	}

	var tasks []ScheduledTask
	for _, row := range rows[1:] {
		taskName := safe(row, idxName)
		if taskName == "" {
			continue
		}
		if strings.HasPrefix(taskName, `\Microsoft\`) {
			continue
		}
		author := safe(row, idxAuthor)
		if strings.HasPrefix(strings.ToLower(author), "microsoft") {
			continue
		}
		tasks = append(tasks, ScheduledTask{
			TaskName:  taskName,
			TaskToRun: safe(row, idxRun),
			Author:    author,
			RunAsUser: safe(row, idxRunAs),
			Status:    safe(row, idxStatus),
		})
	}
	return tasks
}
