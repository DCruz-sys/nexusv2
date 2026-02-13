package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

type Task struct {
	ID           string   `json:"id"`
	Priority     int      `json:"priority"`
	Dependencies []string `json:"dependencies"`
	Agent        string   `json:"agent"`
}

type PlannerInput struct {
	Tasks       []Task `json:"tasks"`
	MaxParallel int    `json:"max_parallel"`
}

type PlannerOutput struct {
	Waves [][]string `json:"waves"`
	Error string     `json:"error,omitempty"`
}

func main() {
	in, err := readInput()
	if err != nil {
		writeOutput(PlannerOutput{Waves: [][]string{}, Error: err.Error()})
		os.Exit(1)
	}

	waves, err := planWaves(in.Tasks, in.MaxParallel)
	if err != nil {
		writeOutput(PlannerOutput{Waves: [][]string{}, Error: err.Error()})
		os.Exit(1)
	}

	writeOutput(PlannerOutput{Waves: waves})
}

func readInput() (PlannerInput, error) {
	reader := bufio.NewReader(os.Stdin)
	decoder := json.NewDecoder(reader)
	var input PlannerInput
	if err := decoder.Decode(&input); err != nil {
		return PlannerInput{}, fmt.Errorf("invalid input: %w", err)
	}
	if input.MaxParallel <= 0 {
		input.MaxParallel = 8
	}
	return input, nil
}

func writeOutput(out PlannerOutput) {
	encoder := json.NewEncoder(os.Stdout)
	_ = encoder.Encode(out)
}

func planWaves(tasks []Task, maxParallel int) ([][]string, error) {
	if len(tasks) == 0 {
		return [][]string{}, nil
	}
	if maxParallel <= 0 {
		maxParallel = 1
	}

	byID := make(map[string]Task, len(tasks))
	indegree := make(map[string]int, len(tasks))
	dependents := make(map[string][]string, len(tasks))

	for _, task := range tasks {
		if task.ID == "" {
			return nil, fmt.Errorf("task id must not be empty")
		}
		byID[task.ID] = task
		indegree[task.ID] = 0
	}

	for _, task := range tasks {
		for _, dep := range task.Dependencies {
			if _, ok := byID[dep]; !ok {
				continue
			}
			indegree[task.ID]++
			dependents[dep] = append(dependents[dep], task.ID)
		}
	}

	available := make([]string, 0, len(tasks))
	for _, task := range tasks {
		if indegree[task.ID] == 0 {
			available = append(available, task.ID)
		}
	}

	visited := 0
	waves := make([][]string, 0)
	for len(available) > 0 {
		sort.SliceStable(available, func(i, j int) bool {
			ti := byID[available[i]]
			tj := byID[available[j]]
			if ti.Priority != tj.Priority {
				return ti.Priority > tj.Priority
			}
			return ti.ID < tj.ID
		})

		waveSize := maxParallel
		if len(available) < waveSize {
			waveSize = len(available)
		}

		wave := make([]string, waveSize)
		copy(wave, available[:waveSize])
		waves = append(waves, wave)
		available = available[waveSize:]

		for _, current := range wave {
			visited++
			for _, dep := range dependents[current] {
				indegree[dep]--
				if indegree[dep] == 0 {
					available = append(available, dep)
				}
			}
		}
	}

	if visited != len(tasks) {
		unresolved := make([]string, 0)
		for id, in := range indegree {
			if in > 0 {
				unresolved = append(unresolved, id)
			}
		}
		sort.Strings(unresolved)
		return nil, fmt.Errorf("cycle detected in task graph: %v", unresolved)
	}

	return waves, nil
}
