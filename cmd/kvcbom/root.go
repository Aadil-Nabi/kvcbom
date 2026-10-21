package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/Aadil-Nabi/kvcbom/internal/cli"
	"github.com/Aadil-Nabi/kvcbom/internal/version"
)

func newRootCmd() *cobra.Command {
	var (
		logLevel  string
		logFormat string
		noColor   bool
	)

	root := &cobra.Command{
		Use:   "kvcbom",
		Short: "Post-quantum cryptographic readiness assessment from CBOMs",
		Long: "kvcbom consumes CycloneDX 1.6 Cryptographic Bills of Materials (CBOMs),\n" +
			"risk-scores the inventoried cryptographic assets for quantum exposure, and\n" +
			"generates shareable readiness reports. It makes no network calls.",
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			if err := cli.SetupLogger(os.Stderr, logLevel, logFormat, noColor); err != nil {
				return cli.Coded(cli.ExitUsage, err)
			}
			return nil
		},
	}

	root.PersistentFlags().StringVar(&logLevel, "log-level", "info", "log level: debug|info|warn|error")
	root.PersistentFlags().StringVar(&logFormat, "log-format", "text", "log format: text|json")
	root.PersistentFlags().BoolVar(&noColor, "no-color", false, "disable coloured output")
	// --config is reserved for the config-file layer (added with the report command).
	root.PersistentFlags().String("config", "", "path to a config file")

	root.AddCommand(newValidateCmd())
	root.AddCommand(newReportCmd())
	root.AddCommand(newDiffCmd())
	root.AddCommand(newRulepacksCmd())
	root.AddCommand(newVersionCmd())
	return root
}
