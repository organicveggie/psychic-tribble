package cmd

import (
	"fmt"

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
	verbose  bool

	rootCmd = &cobra.Command{
		Use:   "psychic-tribble",
		Short: "Generate metrics for restic-backup",
		Long: `psychic-tribble is a CLI tool which produces metrics around the execution
of restic-backup.`,
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

	viper.BindPFlag(flagUnitName, rootCmd.PersistentFlags().Lookup(flagUnitName))
	viper.BindPFlag(flagVerbose, rootCmd.PersistentFlags().Lookup(flagVerbose))
	viper.SetDefault(flagUnitName, defaultUnit)
	viper.SetDefault(flagVerbose, defaultVerbose)
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
