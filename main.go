package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/mtaku3/kubecerts/pkg/ca"
	"github.com/mtaku3/kubecerts/pkg/manager"
	"github.com/mtaku3/kubecerts/pkg/nix"
	"github.com/urfave/cli/v3"
	"gopkg.in/yaml.v2"
)

func main() {
	cmd := &cli.Command{
		Name:        "kubecerts",
		Usage:       "Kubernetes certificate management tool with Age encryption",
		Description: "A tool for managing Kubernetes PKI certificates with Age encryption and NixOS integration",
		Commands: []*cli.Command{
			{
				Name:  "hosts",
				Usage: "List Kubernetes hosts from Nix configurations",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					// Test host discovery without age dependency
					flakeParser := nix.NewFlakeParser(".")
					hosts, err := flakeParser.DiscoverHosts(ctx)
					if err != nil {
						return err
					}
					fmt.Println("Retrieved hosts:", hosts)
					return nil
				},
			},
			{
				Name:  "status",
				Usage: "Check certificate status across all hosts",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "flake",
						Aliases: []string{"f"},
						Value:   ".",
						Usage:   "Path to Nix flake",
					},
					&cli.StringFlag{
						Name:    "secrets-dir",
						Aliases: []string{"s"},
						Value:   "./secrets",
						Usage:   "Secrets directory containing encrypted certificates",
					},
					&cli.StringFlag{
						Name:    "age-key",
						Aliases: []string{"k"},
						Value:   "",
						Usage:   "Path to age identity file",
					},
					&cli.StringFlag{
						Name:  "format",
						Value: "text",
						Usage: "Output format: text, json, yaml",
					},
				},
				Action: showStatus,
			},
			{
				Name:  "renew",
				Usage: "Renew CA certificates",
				Commands: []*cli.Command{
					{
						Name:  "ca",
						Usage: "Renew CA certificates",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:    "flake",
								Aliases: []string{"f"},
								Value:   ".",
								Usage:   "Path to Nix flake",
							},
							&cli.StringFlag{
								Name:    "secrets-dir",
								Aliases: []string{"s"},
								Value:   "./secrets",
								Usage:   "Secrets directory",
							},
							&cli.StringFlag{
								Name:    "age-key",
								Aliases: []string{"k"},
								Value:   "",
								Usage:   "Path to age identity file",
							},
						},
						Action: renewCertificates,
					},
				},
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return cli.ShowAppHelp(cmd)
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}

// CLI action functions

// showStatus shows certificate status across all hosts
func showStatus(ctx context.Context, cmd *cli.Command) error {
	flakePath := cmd.String("flake")
	secretsDir := cmd.String("secrets-dir")
	ageKeyPath := cmd.String("age-key")
	format := cmd.String("format")

	if ageKeyPath == "" {
		return fmt.Errorf("age-key is required")
	}

	// Create manager
	mgr, err := manager.New(&manager.Config{
		FlakePath:  flakePath,
		SecretsDir: secretsDir,
		AgeKeyPath: ageKeyPath,
	})
	if err != nil {
		return fmt.Errorf("failed to create manager: %w", err)
	}

	// Get status using existing manager interface
	status, err := mgr.GetCertificateStatus(ctx)
	if err != nil {
		return fmt.Errorf("failed to get status: %w", err)
	}

	// Output in requested format
	switch format {
	case "json":
		return outputJSON(status)
	case "yaml":
		return outputYAML(status)
	default:
		return printTextStatus(status)
	}
}

func renewCertificates(ctx context.Context, cmd *cli.Command) error {
	flakePath := cmd.String("flake")
	secretsDir := cmd.String("secrets-dir")
	ageKeyPath := cmd.String("age-key")

	if ageKeyPath == "" {
		return fmt.Errorf("age-key is required")
	}

	// Parse CA type from args - matches existing pattern
	caTypes := ca.AllCATypes() // default to all
	if cmd.Args().Len() > 0 {
		arg := cmd.Args().Get(0)
		if arg != "all" {
			caType := ca.CAType(arg)
			if !caType.IsValid() {
				return fmt.Errorf("invalid CA type: %s (valid: %s)", arg, strings.Join(getValidCATypeStrings(), ", "))
			}
			caTypes = []ca.CAType{caType}
		}
	}

	// Create manager
	mgr, err := manager.New(&manager.Config{
		FlakePath:  flakePath,
		SecretsDir: secretsDir,
		AgeKeyPath: ageKeyPath,
	})
	if err != nil {
		return fmt.Errorf("failed to create manager: %w", err)
	}

	// Renew certificates
	result, err := mgr.RenewCertificates(ctx, caTypes)
	if err != nil {
		return fmt.Errorf("failed to renew certificates: %w", err)
	}

	return printRenewResult(result)
}

func outputJSON(status *manager.StatusResult) error {
	return json.NewEncoder(os.Stdout).Encode(status)
}

func outputYAML(status *manager.StatusResult) error {
	return yaml.NewEncoder(os.Stdout).Encode(status)
}

func printTextStatus(result *manager.StatusResult) error {
	fmt.Println("Kubernetes CA Certificate Status")
	fmt.Println("===============================")
	fmt.Println()

	// Print header with CSR validation column
	fmt.Printf("%-21s %-14s %-12s %-13s %-13s %-10s\n", "HOST", "CA_TYPE", "STATUS", "VALID_UNTIL", "RESIDUAL", "CSR_VALID")

	for _, hostResult := range result.HostResults {
		for _, certResult := range hostResult.Certificates {
			hostName := fmt.Sprintf("%s/%s", hostResult.Host.System, hostResult.Host.Name)

			status := "OK"
			if certResult.Status == manager.HealthCritical {
				status = "EXPIRED"
			} else if certResult.Status == manager.HealthWarning {
				if certResult.Error == "Certificate file not found" {
					status = "NOT_FOUND"
				} else {
					status = "WARNING"
				}
			}

			validUntil := ""
			residual := ""
			if !certResult.ValidUntil.IsZero() {
				validUntil = certResult.ValidUntil.Format("2006-01-02")
				days := int(time.Until(certResult.ValidUntil).Hours() / 24)
				if days < 0 {
					residual = "EXPIRED"
				} else if days == 0 {
					residual = "TODAY"
				} else {
					residual = fmt.Sprintf("%dd", days)
				}
			}

			// CSR validation status
			csrStatus := "N/A"
			if certResult.CSRValid != nil {
				if *certResult.CSRValid {
					csrStatus = "OK"
				} else {
					csrStatus = "FAIL"
				}
			}

			fmt.Printf("%-21s %-14s %-12s %-13s %-13s %-10s\n",
				hostName,
				string(certResult.CAType),
				status,
				validUntil,
				residual,
				csrStatus,
			)

			// Show CSR error details if present
			if certResult.CSRError != "" {
				fmt.Printf("    CSR Error: %s\n", certResult.CSRError)
			}
		}
	}

	// Print summary
	fmt.Printf("\nSummary:\n")
	if result.Summary.ExpiredCount > 0 {
		fmt.Printf("  - %d expired certificate(s)\n", result.Summary.ExpiredCount)
	}
	if result.Summary.NotFoundCount > 0 {
		fmt.Printf("  - %d missing certificate(s)\n", result.Summary.NotFoundCount)
	}
	if result.Summary.WarningCount > 0 {
		fmt.Printf("  - %d warning(s)\n", result.Summary.WarningCount)
	}
	if len(result.Summary.ConsistencyIssues) > 0 {
		fmt.Printf("  - %d consistency issue(s)\n", len(result.Summary.ConsistencyIssues))
	}
	if result.Summary.ExpiredCount == 0 && result.Summary.NotFoundCount == 0 && result.Summary.WarningCount == 0 && len(result.Summary.ConsistencyIssues) == 0 {
		fmt.Println("  - All certificates OK")
	}

	// Print detailed consistency issues if present
	if len(result.Summary.ConsistencyIssues) > 0 {
		fmt.Printf("\nConsistency Issues:\n")
		for _, issue := range result.Summary.ConsistencyIssues {
			fmt.Printf("  - %s: %s\n", issue.CAType, issue.Description)
		}
	}

	return nil
}

func printRenewResult(result *manager.RenewResult) error {
	fmt.Println("Renewing CA Certificates")
	fmt.Println("========================")
	fmt.Println()

	for _, op := range result.Operations {
		fmt.Printf("✓ Generated new %s certificate (Valid: %s → %s)\n",
			string(op.CAType),
			op.ValidFrom.Format("2006-01-02"),
			op.ValidUntil.Format("2006-01-02"),
		)
	}

	fmt.Println("\nSyncing to hosts...")
	for _, host := range result.Summary.UpdatedHosts {
		fmt.Printf("✓ %s/%s (%d certificates)\n",
			host.System, host.Name, result.Summary.CertificatesRenewed)
	}

	fmt.Printf("\nRenewal completed successfully!\n")
	fmt.Printf("- Renewed: %d CAs\n", result.Summary.CertificatesRenewed)
	fmt.Printf("- Updated: %d hosts\n", len(result.Summary.UpdatedHosts))

	return nil
}

func getValidCATypeStrings() []string {
	types := ca.AllCATypes()
	result := make([]string, len(types))
	for i, t := range types {
		result[i] = string(t)
	}
	return result
}
