//go:build !windows

package system

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

func Collect() SystemState { return SystemState{} }
