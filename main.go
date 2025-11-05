package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/urfave/cli/v3"
)

type KubernetesRole int

const (
	Master KubernetesRole = iota
	Node
)

func (r *KubernetesRole) FromString(s string) {
	switch s {
	case "node":
		*r = Node
	case "master":
	default:
		*r = Master
	}
}

func (r KubernetesRole) String() string {
	switch r {
	case Master:
		return "master"
	case Node:
		return "node"
	default:
		return "unknown"
	}
}

type Host struct {
	Name        string
	System      string
	AdvertiseIP string
	Role        KubernetesRole
}

func GetHosts() ([]Host, error) {
	cmd := exec.Command("nix", "eval", "--json", ".#nixosConfigurations", "--apply", "builtins.attrNames")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("Failed to retrieve hosts from nix: %w", err)
	}

	var hostNames []string
	if err := json.Unmarshal(out, &hostNames); err != nil {
		return nil, fmt.Errorf("Failed to parse nix eval output: %w", err)
	}

	var hosts []Host
	for _, hostName := range hostNames {
		cmd := exec.Command("nix", "eval", fmt.Sprintf(".#nixosConfigurations.%s.config.capybara.app.server.kubernetes.enable", hostName))
		out, err := cmd.Output()
		isKubernetesEnabled := strings.TrimSpace(string(out))
		if err != nil {
			return nil, fmt.Errorf("Failed to check if kubernetes is enabled for host %s: %w", hostName, err)
		}
		if string(isKubernetesEnabled) != "true" {
			continue
		}

		cmd = exec.Command("nix", "eval", "--raw", fmt.Sprintf(".#nixosConfigurations.%s.config.nixpkgs.system", hostName))
		out, err = cmd.Output()
		system := strings.TrimSpace(string(out))
		if err != nil {
			return nil, fmt.Errorf("Failed to get system from host: %w", err)
		}

		cmd = exec.Command("nix", "eval", "--raw", fmt.Sprintf(".#nixosConfigurations.%s.config.capybara.app.server.kubernetes.advertiseIP", hostName))
		out, err = cmd.Output()
		advertiseIP := strings.TrimSpace(string(out))
		if err != nil {
			return nil, fmt.Errorf("Failed to get advertiseIP from host: %w", err)
		}

		cmd = exec.Command("nix", "eval", "--raw", fmt.Sprintf(".#nixosConfigurations.%s.config.capybara.app.server.kubernetes.role", hostName))
		out, err = cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("Failed to get kubernetes role from host: %w", err)
		}
		var role KubernetesRole
		role.FromString(strings.TrimSpace(string(out)))

		hosts = append(hosts, Host{
			Name:        hostName,
			System:      system,
			AdvertiseIP: advertiseIP,
			Role:        role,
		})
	}

	return hosts, nil
}

func main() {
	cmd := &cli.Command{
		Name: "kubecerts",
		Action: func(context.Context, *cli.Command) error {
			hosts, err := GetHosts()
			if err != nil {
				return err
			}
			fmt.Println("Retrieved hosts: ", hosts)
			return nil
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
