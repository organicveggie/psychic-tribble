package telegraf

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/apex/log"
)

const (
	metricURLPath = "/api/v2/write"
	contentType   = "application/x-www-form-urlencoded"
)

type Client struct {
	client     *http.Client
	rawBaseURL string // base URL of form http://ipaddr:port with no trailing slash
	baseURL    *url.URL
}

// NewClient creates a new Telegraf client from an HTTP client connection.
func NewClient(client *http.Client, baseURL string) *Client {
	c := &Client{
		client:     client,
		rawBaseURL: baseURL,
	}
	c.baseURL, _ = url.Parse(c.rawBaseURL)
	return c
}

type KeyValue struct {
	key   string
	value interface{}
}

func MakeKV(k string, v interface{}) KeyValue {
	return KeyValue{
		key:   k,
		value: v,
	}
}

func (kv KeyValue) ToString() (string, error) {
	var b strings.Builder
	b.WriteString(kv.key)
	b.WriteString("=")
	switch vv := kv.value.(type) {
	case string:
		b.WriteString(fmt.Sprintf("\"%s\"", vv))
	case int:
		b.WriteString(fmt.Sprint(vv))
	case int8:
		b.WriteString(fmt.Sprint(vv))
	case int16:
		b.WriteString(fmt.Sprint(vv))
	case int32:
		b.WriteString(fmt.Sprint(vv))
	case int64:
		b.WriteString(fmt.Sprint(vv))
	case uint:
		b.WriteString(fmt.Sprint(vv))
	case uint8:
		b.WriteString(fmt.Sprint(vv))
	case uint16:
		b.WriteString(fmt.Sprint(vv))
	case uint32:
		b.WriteString(fmt.Sprint(vv))
	case uint64:
		b.WriteString(fmt.Sprint(vv))
	default:
		return "", fmt.Errorf("unsupported type: %#v", vv)
	}
	return b.String(), nil
}

func (c *Client) WriteMetric(metric string, tags []KeyValue, fields []KeyValue,
	timestamp time.Time) error {
	if len(metric) == 0 {
		return fmt.Errorf("missing required metric name")
	}
	if len(fields) == 0 {
		return fmt.Errorf("missing required metric fields for %q", metric)
	}

	// <measurement>[,<tag_key>=<tag_value>[,<tag_key>=<tag_value>]] <field_key>=<field_value>[,<field_key>=<field_value>] [<timestamp>]
	var b strings.Builder
	b.WriteString(metric)
	for _, tag := range tags {
		s, e := tag.ToString()
		if e != nil {
			log.Errorf("Unable to convert tag %q / %v: %v", tag.key, tag.value, e)
			continue
		}
		b.WriteString(",")
		b.WriteString(s)
	}

	b.WriteString(" ")

	fieldCount := len(fields) - 1
	for i, field := range fields {
		s, e := field.ToString()
		if e != nil {
			log.Errorf("Unable to convert field %q / %v: %v", field.key, field.value, e)
			continue
		}
		b.WriteString(s)

		if i < fieldCount {
			b.WriteString(",")
		}
	}

	b.WriteString(" ")
	b.WriteString(fmt.Sprint(timestamp.UnixNano()))

	metricURL, err := c.baseURL.Parse(metricURLPath)
	if err != nil {
		return fmt.Errorf("unexpected error parsing URL path %q: %w", metricURLPath, err)
	}

	resp, err := c.client.Post(metricURL.String(), contentType, strings.NewReader(b.String()))
	if err != nil {
		return fmt.Errorf("error posting metric %q to %q: %w", metric, metricURL, err)
	}
	defer resp.Body.Close()

	return nil
}
