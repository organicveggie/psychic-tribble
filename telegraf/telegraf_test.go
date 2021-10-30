package telegraf_test

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/organicveggie/psychic-tribble/telegraf"
)

var (
	time1 = time.Date(2021, 10, 26, 21, 49, 17, 0, time.UTC)
)

func TestWriteMetric(t *testing.T) {
	var tests = []struct {
		name      string
		metric    string
		tags      []telegraf.KeyValue
		fields    []telegraf.KeyValue
		timestamp time.Time
		wantErr   bool
		wantReq   string
	}{
		{
			name:      "MissingMetricName",
			metric:    "",
			tags:      make([]telegraf.KeyValue, 0),
			fields:    []telegraf.KeyValue{telegraf.MakeKV("key", "value")},
			timestamp: time.Now(),
			wantErr:   true,
		},
		{
			name:      "MissingFields",
			metric:    "test-metric",
			tags:      make([]telegraf.KeyValue, 0),
			fields:    make([]telegraf.KeyValue, 0),
			timestamp: time.Now(),
			wantErr:   true,
		},
		{
			name:      "OneStrringField",
			metric:    "test-metric",
			tags:      make([]telegraf.KeyValue, 0),
			fields:    []telegraf.KeyValue{telegraf.MakeKV("key", "value")},
			timestamp: time1,
			wantErr:   false,
			wantReq:   fmt.Sprintf("test-metric key=\"value\" %d", time1.UnixNano()),
		},
		{
			name:      "OneFloatField",
			metric:    "test-metric",
			tags:      make([]telegraf.KeyValue, 0),
			fields:    []telegraf.KeyValue{telegraf.MakeKV("key", 6.08135)},
			timestamp: time1,
			wantErr:   false,
			wantReq:   fmt.Sprintf("test-metric key=6.08135 %d", time1.UnixNano()),
		},
		{
			name:   "TwoFields",
			metric: "test-metric",
			tags:   make([]telegraf.KeyValue, 0),
			fields: []telegraf.KeyValue{
				telegraf.MakeKV("key", "value"),
				telegraf.MakeKV("foo", 42),
			},
			timestamp: time1,
			wantErr:   false,
			wantReq:   fmt.Sprintf("test-metric key=\"value\",foo=42 %d", time1.UnixNano()),
		},
		{
			name:      "OneFieldOneTag",
			metric:    "test-metric",
			tags:      []telegraf.KeyValue{telegraf.MakeKV("tag", "t1")},
			fields:    []telegraf.KeyValue{telegraf.MakeKV("key", "value")},
			timestamp: time1,
			wantErr:   false,
			wantReq:   fmt.Sprintf("test-metric,tag=\"t1\" key=\"value\" %d", time1.UnixNano()),
		},
		{
			name:   "OneFieldTwoTags",
			metric: "test-metric",
			tags: []telegraf.KeyValue{
				telegraf.MakeKV("tag1", "t1"),
				telegraf.MakeKV("tag2", 2),
			},
			fields:    []telegraf.KeyValue{telegraf.MakeKV("key", "value")},
			timestamp: time1,
			wantErr:   false,
			wantReq:   fmt.Sprintf("test-metric,tag1=\"t1\",tag2=2 key=\"value\" %d", time1.UnixNano()),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Start a local HTTP server
			server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				if req.Method != "POST" {
					t.Errorf("wrong HTTP method type: %s", req.Method)
				}
				if test.wantReq != "" {
					data, err := ioutil.ReadAll(req.Body)
					if err != nil {
						t.Errorf("unexpected error reading request body: %v", err)
					}

					var b strings.Builder
					b.Write(data)
					if test.wantReq != b.String() {
						t.Errorf("Mismatch in server requests. Expected: %s\nGot: %s", test.wantReq, b.String())
					}
				}

				// Send response to be tested
				rw.Write([]byte(`OK`))
			}))
			// Close the server when test finishes
			defer server.Close()

			tc := telegraf.NewClient(server.Client(), server.URL, false)
			err := tc.WriteMetric(test.metric, test.tags, test.fields, test.timestamp)
			if test.wantErr != (err != nil) {
				t.Errorf("WriteMetric() error mismatch. expected: %t, got: %v", test.wantErr, err)
			}
		})
	}
}
