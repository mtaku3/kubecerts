package main

import (
	"os"

	"github.com/mtaku3/kubecerts/pkg/cmd"
	"github.com/sirupsen/logrus"
)

func main() {
	// Configure logging
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	logrus.SetLevel(logrus.InfoLevel)

	// Create and execute root command
	rootCmd := cmd.NewRootCommand()
	if err := rootCmd.Execute(); err != nil {
		logrus.Error(err)
		os.Exit(1)
	}
}