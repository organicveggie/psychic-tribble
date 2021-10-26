package cmd

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"github.com/apex/log"
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
	if verbose {
		log.SetLevel(log.DebugLevel)
	}

	// Retrieve last invocation of backup
	id, err := getLastInvocationId(unitName, verbose)
	if err != nil {
		return err
	}

	log.Infof("InvocationID: %q", id)
	ctx := log.WithField("invocation_id", id)

	// Retrieve logs from last invocation
	logs, err := getJournalLogs(ctx, id)
	if err != nil {
		return err
	}
	ctx.Infof("Journal logs: %s", logs)

	return nil
}

func getLastInvocationId(unitName string, verbose bool) (id string, err error) {
	ctx := log.WithField("unit_name", unitName)

	c := exec.Command("/usr/bin/systemctl", "show", "-p", "InvocationID", "--value", unitName)
	ctx.Debugf("Command: %s", c.String())

	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out
	if err = c.Run(); err != nil {
		return "", fmt.Errorf("error running systemctl for %q: %w", unitName, err)
	}

	return strings.TrimSpace(out.String()), nil
}

func getJournalLogs(ctx log.Interface, invocationId string) (logs string, err error) {
	filter := fmt.Sprintf("_SYSTEMD_INVOCATION_ID=%s", invocationId)
	c := exec.Command("/usr/bin/journalctl", "-o", "short-iso", filter, "--output", "json")
	ctx.Debugf("Commnand: %q", c.String())

	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out
	if err = c.Run(); err != nil {
		return "", fmt.Errorf("error running journalctl for InvocationId %s: %w", invocationId, err)
	}

	return out.String(), nil
}
