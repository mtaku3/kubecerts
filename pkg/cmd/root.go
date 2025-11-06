package cmd

import (
	"github.com/spf13/cobra"
)

// NewRootCommand creates the root command for kubecerts
func NewRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kubecerts",
		Short: "Kubernetes certificate management tool for NixOS with agenix integration",
		Long: `kubecerts is a command-line tool for managing Kubernetes cluster certificates.
It integrates with NixOS flakes for host discovery and uses agenix for secure
certificate storage and distribution.`,
		SilenceUsage: true,
	}

	// Add subcommands
	cmd.AddCommand(NewCertsCommand())
	cmd.AddCommand(NewCheckCommand())
	cmd.AddCommand(NewRenewCommand())
	cmd.AddCommand(NewListCommand())

	return cmd
}