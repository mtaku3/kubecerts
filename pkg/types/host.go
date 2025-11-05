package types

import "fmt"

type Host struct {
	System string `json:"system"` // x86_64-linux, aarch64-linux
	Name   string `json:"name"`   // node1, worker1
}

func (h Host) String() string {
	return fmt.Sprintf("%s/%s", h.System, h.Name)
}