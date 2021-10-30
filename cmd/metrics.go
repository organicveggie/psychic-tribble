package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/organicveggie/psychic-tribble/telegraf"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	defaultDryRun      = false
	defaultTelegrafURL = "http://localhost:8086"
	defaultUnit        = "restic-backup.service"

	DefaultJournalctlBin = "/usr/bin/journalctl"
	DefaultSystemctlBin  = "/usr/bin/systemctl"

	flagNameDryRun      = "dryrun"
	flagNameTelegrafURL = "telegraf"
	flagNameUnitName    = "unitname"

	flagNameJournalctlBin = "journalctl"
	flagNameSystemctlBin  = "systemctl"
)

var (
	dryRun      bool
	telegrafURL string
	unitName    string

	flagJournalctlBin string
	flagSystemctlBin  string

	metricsCmd = &cobra.Command{
		Use:   "metrics",
		Short: "Generate metrics for restic-backup",
		Long: `Usage: psychic-tribble metrics

Metrics parses the systemd journal logs for the last restic-backup execution
and pushes metrics to Telegraf and InfluxDB.`,
		RunE: runMetrics,
	}

	syslogMsgRegEx = regexp.MustCompile(`^"(?P<message>.+)"$`)
)

type execContext = func(name string, arg ...string) *exec.Cmd

func init() {
	rootCmd.AddCommand(metricsCmd)

	metricsCmd.Flags().BoolVar(&dryRun, flagNameDryRun, defaultDryRun,
		"don't send metrics to Telegraf")
	metricsCmd.Flags().StringVarP(&telegrafURL, flagNameTelegrafURL, "t", defaultTelegrafURL,
		"URL for Telegraf listener in the form http://ipaddr:port")
	metricsCmd.Flags().StringVar(&unitName, flagNameUnitName, defaultUnit,
		"systemd unit name for backup job")

	metricsCmd.Flags().StringVar(&flagJournalctlBin, flagNameJournalctlBin, DefaultJournalctlBin,
		"full pathname for journalctl binary")
	metricsCmd.Flags().StringVar(&flagSystemctlBin, flagNameSystemctlBin, DefaultSystemctlBin,
		"full pathname for systemctl binary")

	viper.BindPFlag(flagNameDryRun, metricsCmd.Flags().Lookup(flagNameDryRun))
	viper.BindPFlag(flagNameTelegrafURL, metricsCmd.Flags().Lookup(flagNameTelegrafURL))
	viper.BindPFlag(flagNameUnitName, metricsCmd.Flags().Lookup(flagNameUnitName))

	viper.BindPFlag(flagNameJournalctlBin, metricsCmd.Flags().Lookup(flagNameJournalctlBin))
	viper.BindPFlag(flagNameSystemctlBin, metricsCmd.Flags().Lookup(flagNameSystemctlBin))

	viper.SetDefault(flagNameDryRun, defaultDryRun)
	viper.SetDefault(flagNameTelegrafURL, defaultTelegrafURL)
	viper.SetDefault(flagNameUnitName, defaultUnit)

	viper.SetDefault(flagNameJournalctlBin, DefaultJournalctlBin)
	viper.SetDefault(flagNameSystemctlBin, DefaultSystemctlBin)
}

func runMetrics(cmd *cobra.Command, args []string) error {
	unitName := viper.GetString(flagNameUnitName)
	verbose := viper.GetBool(flagVerbose)
	if verbose {
		log.SetLevel(log.DebugLevel)
	}

	journalctlBin := viper.GetString(flagNameJournalctlBin)
	systemctlBin := viper.GetString(flagNameSystemctlBin)

	systemd := NewSystemd(exec.Command, unitName, journalctlBin, systemctlBin)
	summaryEntry, err := systemd.GetResticSummary()
	if err != nil {
		return err
	}

	// Build metric tags and fields
	tags := []telegraf.KeyValue{
		telegraf.MakeKV("machine_id", summaryEntry.MachineId),
		telegraf.MakeKV("syslog_id", summaryEntry.SyslogId),
	}

	rm := summaryEntry.Message.ResticMessage
	fields := []telegraf.KeyValue{
		telegraf.MakeKV("invocation_id", summaryEntry.InvocationId),
		telegraf.MakeKV("files_new", rm.FilesNew),
		telegraf.MakeKV("files_changed", rm.FilesChanged),
		telegraf.MakeKV("files_unmodified", rm.FilesUnmodified),
		telegraf.MakeKV("dirs_new", rm.DirsNew),
		telegraf.MakeKV("dirs_changed", rm.DirsChanged),
		telegraf.MakeKV("dirs_unmodified", rm.DirsUnmodified),
		telegraf.MakeKV("total_files_processed", rm.TotalFilesProcessed),
		telegraf.MakeKV("total_bytes_processed", rm.TotalBytesProcessed),
		telegraf.MakeKV("total_duration", fmt.Sprintf("%.2f", rm.TotalDuration)),
		telegraf.MakeKV("snapshot_id", rm.SnapshotId),
		telegraf.MakeKV("systemd_unit", summaryEntry.SystemdUnit),
		telegraf.MakeKV("monotonic_timestamp", summaryEntry.MonotonicTimestamp),
	}

	dryRun := viper.GetBool(flagNameDryRun)

	// Publish metric to Telegraf
	httpClient := &http.Client{}
	telegrafClient := telegraf.NewClient(httpClient, viper.GetString(flagNameTelegrafURL), dryRun)
	if err := telegrafClient.WriteMetric("restic_backup", tags, fields, time.Now()); err != nil {
		return fmt.Errorf("error writing metrics to Telegraf: %w", err)
	}

	return err
}

type systemdRunner struct {
	cmdContext execContext
	unitName   string

	journalctlBin string
	systemctlBin  string
}

func NewSystemd(cmdContext execContext, unitName string, journalctl string, systemctl string) *systemdRunner {
	return &systemdRunner{
		cmdContext:    cmdContext,
		unitName:      unitName,
		journalctlBin: journalctl,
		systemctlBin:  systemctl,
	}
}

func (s *systemdRunner) GetResticSummary() (entry *SyslogEntry, err error) {
	// Retrieve last invocation of backup
	id, err := s.getLastInvocationId()
	if err != nil {
		return nil, err
	}
	log.Infof("InvocationID: %q", id)

	logCtx := log.WithField("invocation_id", id)

	// Retrieve logs from last invocation
	logs, err := s.getJournalLogs(logCtx, id)
	if err != nil {
		return entry, err
	}

	msgs, err := s.convertJournalLogs(logCtx, logs)
	if err != nil {
		return entry, err
	}
	if len(msgs) == 0 {
		return entry, fmt.Errorf("no journal logs found for InvocationId %s", id)
	}
	log.Infof("Found %d log messages", len(msgs))

	for _, m := range msgs {
		if m.Message.ResticMessage != nil && m.Message.ResticMessage.MessageType == "summary" {
			entry = m
			break
		}
	}

	return entry, err
}

func (s *systemdRunner) getLastInvocationId() (id string, err error) {
	ctx := log.WithField("unit_name", s.unitName)

	c := s.cmdContext(s.systemctlBin, "show", "-p", "InvocationID", "--value", s.unitName)
	ctx.Debugf("Command: %s", c.String())

	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out
	if err = c.Run(); err != nil {
		return "", fmt.Errorf("error running systemctl for %q: %w", unitName, err)
	}

	return strings.TrimSpace(out.String()), nil
}

func (s *systemdRunner) getJournalLogs(ctx log.Interface, invocationId string) (logs string, err error) {
	filter := fmt.Sprintf("_SYSTEMD_INVOCATION_ID=%s", invocationId)
	c := s.cmdContext(s.journalctlBin, "-o", "short-iso", filter, "--output", "json")
	ctx.Debugf("Commnand: %q", c.String())

	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out
	if err = c.Run(); err != nil {
		return "", fmt.Errorf("error running %s for InvocationId %s: %w",
			s.journalctlBin, invocationId, err)
	}

	return out.String(), nil
}

func (s *systemdRunner) convertJournalLogs(ctx log.Interface, logs string) ([]*SyslogEntry, error) {
	logLines := strings.Split(logs, "\n")
	if len(logLines) == 0 {
		log.Warnf("Problem processing log messages: %s", logs)
		return nil, fmt.Errorf("empty log messages")
	}

	msgs := make([]*SyslogEntry, 0, len(logLines))
	for _, line := range logLines {
		cleanLine := strings.TrimSpace(line)
		if cleanLine == "" {
			continue
		}

		b := []byte(cleanLine)
		msg, err := syslogMsgFromJSON(ctx, b)
		if err != nil {
			ctx.Warnf("Problem converting: %q", cleanLine)
			return nil, fmt.Errorf("error converting syslog journal message from JSON: %w", err)
		}
		msgs = append(msgs, msg)
	}

	return msgs, nil
}

// SyslogEntry contains the contents of a single systemd journal entry.
type SyslogEntry struct {
	SyslogId           string         `json:"SYSLOG_IDENTIFIER"`
	MonotonicTimestamp uint64         `json:"__MONOTONIC_TIMESTAMP,string"`
	InvocationId       string         `json:"_SYSTEMD_INVOCATION_ID"`
	SystemdUnit        string         `json:"_SYSTEMD_UNIT"`
	MachineId          string         `json:"_MACHINE_ID"`
	Hostname           string         `json:"_HOSTNAME"`
	Message            MessageWrapper `json:"MESSAGE,omitempty"`
}

// MessageWrap handles intercepting MESSAGE field values.
type MessageWrapper struct {
	RawText       string
	ResticMessage *ResticMsg
}

// ResticMsg contains the data from parsed JSON output by the restic backup tool.
type ResticMsg struct {
	MessageType         string  `json:"message_type"`
	FilesNew            uint64  `json:"files_new"`
	FilesChanged        uint64  `json:"files_changed"`
	FilesUnmodified     uint64  `json:"files_unmodified"`
	DirsNew             uint64  `json:"dirs_new"`
	DirsChanged         uint64  `json:"dirs_changed"`
	DirsUnmodified      uint64  `json:"dirs_unmodified"`
	TotalFilesProcessed uint64  `json:"total_files_processed"`
	TotalBytesProcessed uint64  `json:"total_bytes_processed"`
	TotalDuration       float64 `json:"total_duration"`
	SnapshotId          string  `json:"snapshot_id"`
}

func (mw *MessageWrapper) UnmarshalJSON(data []byte) (err error) {
	txt := string(data)
	if txt == "" {
		return err
	}

	rm := resticMessageFromJSON(txt)
	if rm == nil {
		mw.RawText = txt
	} else {
		mw.ResticMessage = rm
	}
	return err
}

func syslogMsgFromJSON(ctx log.Interface, data []byte) (msg *SyslogEntry, err error) {
	msg = new(SyslogEntry)
	if err = json.Unmarshal(data, msg); err != nil {
		return nil, fmt.Errorf("unable to unmarshal JSON: %w", err)
	}

	return msg, err
}

func resticMessageFromJSON(messageTxt string) *ResticMsg {
	if messageTxt == "" {
		return nil
	}

	messageTxt = strings.ReplaceAll(string(messageTxt), `\"`, `"`)
	if syslogMsgRegEx.MatchString(messageTxt) {
		messageTxt = syslogMsgRegEx.ReplaceAllString(messageTxt, "$message")
	}

	msg := new(ResticMsg)
	if err := json.Unmarshal([]byte(messageTxt), msg); err != nil {
		msg = nil
	}

	return msg
}
