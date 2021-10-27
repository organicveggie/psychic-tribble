package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/apex/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	metricTmpl = "restic_backup,machine_id=\"{{.MachineId}}\",syslog_id=\"{{.SyslogId}}\" " +
		"invocation_id=\"{{.InvocationId}}\",files_new={{.FilesNew}},files_changed={{.FilesChanged}}," +
		"files_unmodified={{.FilesUnmodified}},dirs_new={{.DirsNew}},dirs_changed={{.DirsChanged}}," +
		"dirs_unmodified={{.DirsUnmodified}},total_files_processed={{.TotalFilesProcessed}}," +
		"total_bytes_processed={{.TotalBytesProcessed}},total_duration={{.TotalDuration}}," +
		"snapshot_id=\"{{.SnapshotId}}\",systemd_unit=\"{{.SystemdUnit}}\"," +
		"monotonic_timestamp={{.MonotonicTimestamp}} {{.TimestampNano}}"
)

var (
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
	logCtx := log.WithField("invocation_id", id)

	// Retrieve logs from last invocation
	logs, err := getJournalLogs(logCtx, id)
	if err != nil {
		return err
	}

	msgs, err := convertJournalLogs(logCtx, logs)
	if err != nil {
		return err
	}
	if len(msgs) == 0 {
		return fmt.Errorf("no journal logs found for InvocationId %s", id)
	}
	log.Infof("Found %d log messages", len(msgs))

	// Find the summary data record
	var summaryEntry *syslogEntry
	for _, m := range msgs {
		if m.Message.resticMessage.MessageType == "summary" {
			summaryEntry = m
		}
	}

	// Publish metric to Telegraf
	err = writeMetric(context.Background(), metricFromSyslogEntry(summaryEntry, time.Now()))

	return err
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

func convertJournalLogs(ctx log.Interface, logs string) ([]*syslogEntry, error) {
	logLines := strings.Split(logs, "\n")
	if len(logLines) == 0 {
		log.Warnf("Problem processing log messages: %s", logs)
		return nil, fmt.Errorf("empty log messages")
	}

	msgs := make([]*syslogEntry, 0, len(logLines))
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

func writeMetric(ctx context.Context, metric *backupMetric) error {
	tmpl, err := template.New("metricTemplate").Parse(metricTmpl)
	if err != nil {
		return fmt.Errorf("error parsing metric template: %w", err)
	}

	b := new(strings.Builder)
	err = tmpl.Execute(b, metric)
	if err != nil {
		return fmt.Errorf("error executing template: %w", err)
	}

	client := &http.Client{}
	resp, err := client.Post("http://localhost:8086", "text", strings.NewReader(b.String()))
	if err != nil {
		return fmt.Errorf("error sending metrics to Telegraf: %w", err)
	}
	defer resp.Body.Close()

	return nil
}

// {"SYSLOG_IDENTIFIER":"restic-forget.sh","__MONOTONIC_TIMESTAMP":"86509367037","PRIORITY":"6",
// "_CMDLINE":"/bin/bash /usr/local/sbin/restic-forget.sh","_SYSTEMD_INVOCATION_ID":"49ea307296c74e3fa1365dd62862f69e",
//"_SYSTEMD_UNIT":"restic-backup.service","_COMM":"restic-forget.s","_UID":"0","_MACHINE_ID":"f4995a7ba0ad462a999441ac1c4dde5e",
// "_SYSTEMD_CGROUP":"/system.slice/restic-backup.service","MESSAGE":"Finished restic snapshot removal","_TRANSPORT":"stdout",
// "SYSLOG_FACILITY":"3","_EXE":"/usr/bin/bash","_GID":"0","_SYSTEMD_SLICE":"system.slice","_HOSTNAME":"Z97X-UD5H","_PID":"338731",
// "_BOOT_ID":"9d572844f08843b2988fe83d5dfea7ec","_SELINUX_CONTEXT":"unconfined\n","_STREAM_ID":"bf3a79979ab34b16bb2323963da67f82",
// "__CURSOR":"s=758865288d214086be7ab7f33762d9ec;i=22a0;b=9d572844f08843b2988fe83d5dfea7ec;m=14245c2efd;t=5cf3552f84f6b;x=5d5942d128b745a8",
// "__REALTIME_TIMESTAMP":"1635202815774571","_CAP_EFFECTIVE":"3bfffeffff"}
type syslogEntry struct {
	SyslogId           string        `json:"SYSLOG_IDENTIFIER"`
	MonotonicTimestamp uint64        `json:"__MONOTONIC_TIMESTAMP,string"`
	InvocationId       string        `json:"_SYSTEMD_INVOCATION_ID"`
	SystemdUnit        string        `json:"_SYSTEMD_UNIT"`
	MachineId          string        `json:"_MACHINE_ID"`
	Hostname           string        `json:"_HOSTNAME"`
	Message            syslogMessage `json:"MESSAGE,omitempty"`
}

type syslogMessage struct {
	message       string
	resticMessage resticMsg
}

// "{\"message_type\":\"summary\",\"files_new\":0,\"files_changed\":4,\"files_unmodified\":68439,
// \"dirs_new\":0,\"dirs_changed\":7,\"dirs_unmodified\":18213,
// \"data_blobs\":3,\"tree_blobs\":8,\"data_added\":970764,
// \"total_files_processed\":68443,\"total_bytes_processed\":2770780704,\"total_duration\":5.900547246,
// \"snapshot_id\":\"78c5a2c5\"}"
type resticMsg struct {
	MessageType         string `json:"message_type"`
	FilesNew            uint64 `json:"files_new"`
	FilesChanged        uint64 `json:"files_changed"`
	FilesUnmodified     uint64 `json:"files_unmodified"`
	DirsNew             uint64 `json:"dirs_new"`
	DirsChanged         uint64 `json:"dirs_changed"`
	DirsUnmodified      uint64 `json:"dirs_unmodified"`
	TotalFilesProcessed uint64 `json:"total_files_processed"`
	TotalBytesProcessed uint64 `json:"total_bytes_processed"`
	TotalDuration       uint64 `json:"total_duration"`
	SnapshotId          string `json:"snapshot_id"`
}

func (sm *syslogMessage) UnmarshalJSON(data []byte) (err error) {
	if len(data) == 0 {
		return nil
	}

	sm.message = strings.ReplaceAll(string(data), `\"`, `"`)
	if syslogMsgRegEx.MatchString(sm.message) {
		sm.message = syslogMsgRegEx.ReplaceAllString(sm.message, "$message")
	}

	if err := json.Unmarshal([]byte(sm.message), &sm.resticMessage); err == nil {
		sm.message = ""
	}
	return nil
}

func syslogMsgFromJSON(ctx log.Interface, data []byte) (msg *syslogEntry, err error) {
	msg = new(syslogEntry)
	if err = json.Unmarshal(data, msg); err != nil {
		return nil, fmt.Errorf("unable to unmarshal JSON: %w", err)
	}

	return msg, err
}

type backupMetric struct {
	DirsNew             uint64
	DirsChanged         uint64
	DirsUnmodified      uint64
	FilesChanged        uint64
	FilesNew            uint64
	FilesUnmodified     uint64
	InvocationId        string
	MachineId           string
	MonotonicTimestamp  uint64
	SnapshotId          string
	SyslogId            string
	SystemdUnit         string
	TotalFilesProcessed uint64
	TotalBytesProcessed uint64
	TotalDuration       uint64
	TimestampNano       string
}

func metricFromSyslogEntry(s *syslogEntry, timestamp time.Time) *backupMetric {
	return &backupMetric{
		DirsNew:             s.Message.resticMessage.DirsNew,
		DirsChanged:         s.Message.resticMessage.DirsChanged,
		DirsUnmodified:      s.Message.resticMessage.DirsUnmodified,
		FilesChanged:        s.Message.resticMessage.FilesChanged,
		FilesNew:            s.Message.resticMessage.FilesNew,
		FilesUnmodified:     s.Message.resticMessage.FilesUnmodified,
		InvocationId:        s.InvocationId,
		MachineId:           s.MachineId,
		MonotonicTimestamp:  s.MonotonicTimestamp,
		SnapshotId:          s.Message.resticMessage.SnapshotId,
		SyslogId:            s.SyslogId,
		SystemdUnit:         s.SystemdUnit,
		TotalFilesProcessed: s.Message.resticMessage.TotalFilesProcessed,
		TotalBytesProcessed: s.Message.resticMessage.TotalBytesProcessed,
		TotalDuration:       s.Message.resticMessage.TotalDuration,
		TimestampNano:       fmt.Sprint(timestamp.UnixNano()),
	}
}
