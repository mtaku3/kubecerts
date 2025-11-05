package nix

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/mtaku3/kubecerts/pkg/types"
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

type FlakeHost struct {
	Name        string
	System      string
	AdvertiseIP string
	Role        KubernetesRole
}

type FlakeParser struct {
	flakePath string
}

func NewFlakeParser(flakePath string) *FlakeParser {
	return &FlakeParser{
		flakePath: flakePath,
	}
}

func (p *FlakeParser) DiscoverHosts(ctx context.Context) ([]types.Host, error) {
	// Get all nixosConfiguration names
	cmd := exec.CommandContext(ctx, "nix", "eval", "--json", ".#nixosConfigurations", "--apply", "builtins.attrNames")
	cmd.Dir = p.flakePath
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve hosts from nix: %w", err)
	}

	var hostNames []string
	if err := json.Unmarshal(out, &hostNames); err != nil {
		return nil, fmt.Errorf("failed to parse nix eval output: %w", err)
	}

	var hosts []types.Host
	for _, hostName := range hostNames {
		// Check if kubernetes is enabled
		cmd := exec.CommandContext(ctx, "nix", "eval", 
			fmt.Sprintf(".#nixosConfigurations.%s.config.capybara.app.server.kubernetes.enable", hostName))
		cmd.Dir = p.flakePath
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("failed to check if kubernetes is enabled for host %s: %w", hostName, err)
		}
		
		isKubernetesEnabled := strings.TrimSpace(string(out))
		if isKubernetesEnabled != "true" {
			continue // Skip non-Kubernetes hosts
		}

		// Get system architecture
		cmd = exec.CommandContext(ctx, "nix", "eval", "--raw", 
			fmt.Sprintf(".#nixosConfigurations.%s.config.nixpkgs.system", hostName))
		cmd.Dir = p.flakePath
		out, err = cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("failed to get system from host: %w", err)
		}
		system := strings.TrimSpace(string(out))

		hosts = append(hosts, types.Host{
			Name:   hostName,
			System: system,
		})
	}

	return hosts, nil
}

// DiscoverFullHosts returns hosts with complete information including AdvertiseIP and Role
func (p *FlakeParser) DiscoverFullHosts(ctx context.Context) ([]FlakeHost, error) {
	// Get all nixosConfiguration names
	cmd := exec.CommandContext(ctx, "nix", "eval", "--json", ".#nixosConfigurations", "--apply", "builtins.attrNames")
	cmd.Dir = p.flakePath
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve hosts from nix: %w", err)
	}

	var hostNames []string
	if err := json.Unmarshal(out, &hostNames); err != nil {
		return nil, fmt.Errorf("failed to parse nix eval output: %w", err)
	}

	var hosts []FlakeHost
	for _, hostName := range hostNames {
		// Check if kubernetes is enabled
		cmd := exec.CommandContext(ctx, "nix", "eval", 
			fmt.Sprintf(".#nixosConfigurations.%s.config.capybara.app.server.kubernetes.enable", hostName))
		cmd.Dir = p.flakePath
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("failed to check if kubernetes is enabled for host %s: %w", hostName, err)
		}
		
		isKubernetesEnabled := strings.TrimSpace(string(out))
		if isKubernetesEnabled != "true" {
			continue // Skip non-Kubernetes hosts
		}

		// Get system architecture
		cmd = exec.CommandContext(ctx, "nix", "eval", "--raw", 
			fmt.Sprintf(".#nixosConfigurations.%s.config.nixpkgs.system", hostName))
		cmd.Dir = p.flakePath
		out, err = cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("failed to get system from host: %w", err)
		}
		system := strings.TrimSpace(string(out))

		// Get advertise IP
		cmd = exec.CommandContext(ctx, "nix", "eval", "--raw", 
			fmt.Sprintf(".#nixosConfigurations.%s.config.capybara.app.server.kubernetes.advertiseIP", hostName))
		cmd.Dir = p.flakePath
		out, err = cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("failed to get advertiseIP from host: %w", err)
		}
		advertiseIP := strings.TrimSpace(string(out))

		// Get Kubernetes role
		cmd = exec.CommandContext(ctx, "nix", "eval", "--raw", 
			fmt.Sprintf(".#nixosConfigurations.%s.config.capybara.app.server.kubernetes.role", hostName))
		cmd.Dir = p.flakePath
		out, err = cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("failed to get kubernetes role from host: %w", err)
		}
		
		var role KubernetesRole
		role.FromString(strings.TrimSpace(string(out)))

		hosts = append(hosts, FlakeHost{
			Name:        hostName,
			System:      system,
			AdvertiseIP: advertiseIP,
			Role:        role,
		})
	}

	return hosts, nil
}
