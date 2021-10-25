package cmd

import (
	"bytes"
	"fmt"
	"os/exec"

	"github.com/organicveggie/psychic-tribble/build"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	defaultUnit    = "restic-backup.service"
	defaultVerbose = false

	flagUnitName = "unitname"
	flagVerbose  = "verbose"
)

var (
	cfgFile string

	unitName string
	dryRun   bool
	verbose  bool

	rootCmd = &cobra.Command{
		Use:   "psychic-tribble",
		Short: "Generate metrics for restic-backup",
		Long: `psychic-tribble is a CLI tool which produces metrics around the execution
of restic-backup.`,
	}

	metricsCmd = &cobra.Command{
		Use:   "metrics",
		Short: "Generate metrics for restic-backup",
		Long: `Usage: psychic-tribble metrics

Metrics parses the systemd journal logs for the last restic-backup execution
and pushes metrics to Telegraf and InfluxDB.`,
		RunE: runMetrics,
	}

	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Long:  `Version prints the build information for this binarry.`,
		Run:   runVersion,
	}
)

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file")
	rootCmd.PersistentFlags().StringVar(&unitName, flagUnitName, defaultUnit, "systemd unit name for backup job")
	rootCmd.PersistentFlags().BoolVar(&verbose, flagVerbose, false, "print more information")
	rootCmd.Flags().BoolVarP(&dryRun, "dryrun", "", false, "don't send metrics to Telegraf")

	viper.BindPFlag(flagUnitName, rootCmd.PersistentFlags().Lookup(flagUnitName))
	viper.BindPFlag(flagVerbose, rootCmd.PersistentFlags().Lookup(flagVerbose))
	viper.SetDefault(flagUnitName, defaultUnit)
	viper.SetDefault(flagVerbose, defaultVerbose)

	rootCmd.AddCommand(metricsCmd)
	rootCmd.AddCommand(versionCmd)
}

func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("json")
		viper.AddConfigPath("/etc/psyschic-tribble")
		viper.AddConfigPath("$HOME/.psyschic-tribble")
		viper.AddConfigPath(".")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found
			if cfgFile != "" {
				panic(fmt.Errorf("config file not found: %s", cfgFile))
			}
		} else {
			// Config file was found but another error was produced
			panic(fmt.Errorf("fatal error reading config file: %w", err))
		}
	} else {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

func runMetrics(cmd *cobra.Command, args []string) error {
	unitName := viper.GetString(flagUnitName)
	verbose := viper.GetBool(flagVerbose)

	// Retrieve last invocation of backup
	id, err := getLastInvocationId(unitName, verbose)
	if err != nil {
		return err
	}

	if verbose {
		fmt.Printf("InvocationID: %s\n", id)
	}

	return nil
}

func getLastInvocationId(unitName string, verbose bool) (string, error) {
	c := exec.Command("/usr/bin/systemctl", "show", "-p", "InvocationID", "--value", unitName)

	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out

	if verbose {
		fmt.Println(c.String())
	}
	if err := c.Run(); err != nil {
		return "", fmt.Errorf("error running systemctl for %q: %w", unitName, err)
	}

	return out.String(), nil
}

func runVersion(cmd *cobra.Command, args []string) {
	fmt.Println("Version:\t", build.Version)
	fmt.Println("Commit:\t\t", build.Commit)
	fmt.Println("Build Date:\t", build.Date)
	fmt.Println("Build User:\t", build.BuiltBy)
}
