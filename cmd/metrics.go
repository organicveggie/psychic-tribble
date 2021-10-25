package cmd

import (
	"bytes"
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var metricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Generate metrics for restic-backup",
	Long: `Usage: psychic-tribble metrics

Metrics parses the systemd journal logs for the last restic-backup execution
and pushes metrics to Telegraf and InfluxDB.`,
	RunE: runMetrics,
}

func init() {
	rootCmd.AddCommand(metricsCmd)
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
