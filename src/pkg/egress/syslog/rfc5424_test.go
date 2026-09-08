package syslog_test

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"code.cloudfoundry.org/go-loggregator/v10/rpc/loggregator_v2"
	"code.cloudfoundry.org/loggregator-agent-release/src/pkg/egress/syslog"
)

var _ = Describe("RFC5424", func() {
	var c *syslog.Converter

	BeforeEach(func() {
		c = syslog.NewConverter()
	})

	It("converts a log envelope to a slice of slice of byte in RFC5424 format", func() {
		env := buildLogEnvelope("MY TASK", "2", "just a test", loggregator_v2.Log_OUT)

		Expect(c.ToRFC5424(env, "test-hostname")).To(Equal([][]byte{
			[]byte("<14>1 1970-01-01T00:00:00.012345+00:00 test-hostname test-app-id [MY-TASK/2] - [tags@47450 source_type=\"MY TASK\"] just a test\n"),
		}))
	})

	It("uses the correct priority for STDERR", func() {
		env := buildLogEnvelope("MY TASK", "2", "just a test", loggregator_v2.Log_ERR)

		Expect(c.ToRFC5424(env, "test-hostname")).To(Equal([][]byte{
			[]byte("<11>1 1970-01-01T00:00:00.012345+00:00 test-hostname test-app-id [MY-TASK/2] - [tags@47450 source_type=\"MY TASK\"] just a test\n"),
		}))
	})

	It("uses the correct priority for unknown log type", func() {
		env := buildLogEnvelope("MY TASK", "2", "just a test", 20)

		Expect(c.ToRFC5424(env, "test-hostname")).To(Equal([][]byte{
			[]byte("<-1>1 1970-01-01T00:00:00.012345+00:00 test-hostname test-app-id [MY-TASK/2] - [tags@47450 source_type=\"MY TASK\"] just a test\n"),
		}))
	})

	It("converts a gauge envelope to a slice of slice of byte in RFC5424 format", func() {
		env := buildGaugeEnvelope("1")

		result, err := c.ToRFC5424(env, "test-hostname")
		Expect(err).ToNot(HaveOccurred())
		Expect(result).To(ConsistOf(
			[]byte("<14>1 1970-01-01T00:00:00.012345+00:00 test-hostname test-app-id [1] - [gauge@47450 name=\"cpu\" value=\"0.23\" unit=\"percentage\"] \n"),
			[]byte("<14>1 1970-01-01T00:00:00.012345+00:00 test-hostname test-app-id [1] - [gauge@47450 name=\"disk\" value=\"1234\" unit=\"bytes\"] \n"),
			[]byte("<14>1 1970-01-01T00:00:00.012345+00:00 test-hostname test-app-id [1] - [gauge@47450 name=\"disk_quota\" value=\"1024\" unit=\"bytes\"] \n"),
			[]byte("<14>1 1970-01-01T00:00:00.012345+00:00 test-hostname test-app-id [1] - [gauge@47450 name=\"memory\" value=\"5423\" unit=\"bytes\"] \n"),
			[]byte("<14>1 1970-01-01T00:00:00.012345+00:00 test-hostname test-app-id [1] - [gauge@47450 name=\"memory_quota\" value=\"8000\" unit=\"bytes\"] \n"),
		))
	})

	It("converts a counter envelope to a slice of slice of byte in RFC5424 format", func() {
		env := buildCounterEnvelope("1")

		Expect(c.ToRFC5424(env, "test-hostname")).To(Equal([][]byte{
			[]byte("<14>1 1970-01-01T00:00:00.012345+00:00 test-hostname test-app-id [1] - [counter@47450 name=\"some-counter\" total=\"99\" delta=\"1\"] \n"),
		}))
	})

	It("converts a timer envelope to a slice of slice of byte in RFC5424 format", func() {
		env := buildTimerEnvelope("1")

		Expect(c.ToRFC5424(env, "test-hostname")).To(Equal([][]byte{
			[]byte(`<14>1 1970-01-01T00:00:00.012345+00:00 test-hostname test-app-id [1] - [timer@47450 name="http" start="10" stop="20"] ` + "\n"),
		}))
	})

	It("converts an event envelope to a slice of slice of byte in RFC5424 format", func() {
		env := buildEventEnvelope("1")

		Expect(c.ToRFC5424(env, "test-hostname")).To(Equal([][]byte{
			[]byte(`<14>1 1970-01-01T00:00:00.012345+00:00 test-hostname test-app-id [1] - [event@47450 title="event-title" body="event-body"] ` + "\n"),
		}))
	})

	It("converts tags to the RFC5424 format", func() {
		logEnv := buildLogEnvelope("MY TASK", "2", "just a test", loggregator_v2.Log_ERR)
		logEnv.Tags["log-tag"] = "oyster"

		metricEnv := buildCounterEnvelope("1")
		metricEnv.Tags = map[string]string{"metric-tag": "scallop"}

		receivedMsgs, _ := c.ToRFC5424(logEnv, "test-hostname")
		expectConversion(receivedMsgs, `<11>1 1970-01-01T00:00:00.012345+00:00 test-hostname test-app-id [MY-TASK/2] - [tags@47450 log-tag="oyster" source_type="MY TASK"] just a test`+"\n")

		receivedMsgs, _ = c.ToRFC5424(metricEnv, "test-hostname")
		expectConversion(receivedMsgs, `<14>1 1970-01-01T00:00:00.012345+00:00 test-hostname test-app-id [1] - [counter@47450 name="some-counter" total="99" delta="1"][tags@47450 metric-tag="scallop"] `+"\n")
	})

	It("escapes bad characters in tags", func() {
		logEnv := buildLogEnvelope("MY TASK", "2", "just a test", loggregator_v2.Log_ERR)
		logEnv.Tags["log-tag"] = `"]\`

		metricEnv := buildCounterEnvelope("1")
		metricEnv.Tags = map[string]string{"metric-tag": `"]\`}

		receivedMsgs, _ := c.ToRFC5424(logEnv, "test-hostname")
		expectConversion(receivedMsgs, `<11>1 1970-01-01T00:00:00.012345+00:00 test-hostname test-app-id [MY-TASK/2] - [tags@47450 log-tag="\"\]\\" source_type="MY TASK"] just a test`+"\n")

		receivedMsgs, _ = c.ToRFC5424(metricEnv, "test-hostname")
		expectConversion(receivedMsgs, `<14>1 1970-01-01T00:00:00.012345+00:00 test-hostname test-app-id [1] - [counter@47450 name="some-counter" total="99" delta="1"][tags@47450 metric-tag="\"\]\\"] `+"\n")
	})

	It("has the option to omit tags", func() {
		c = syslog.NewConverter(syslog.WithoutSyslogMetadata())

		logEnv := buildLogEnvelope("MY TASK", "2", "just a test", loggregator_v2.Log_ERR)
		logEnv.Tags["log-tag"] = "oyster"

		metricEnv := buildCounterEnvelope("1")
		metricEnv.Tags = map[string]string{"metric-tag": "scallop"}

		receivedMsgs, _ := c.ToRFC5424(logEnv, "test-hostname")
		expectConversion(receivedMsgs, `<11>1 1970-01-01T00:00:00.012345+00:00 test-hostname test-app-id [MY-TASK/2] - - just a test`+"\n")

		receivedMsgs, _ = c.ToRFC5424(metricEnv, "test-hostname")
		expectConversion(receivedMsgs, `<14>1 1970-01-01T00:00:00.012345+00:00 test-hostname test-app-id [1] - [counter@47450 name="some-counter" total="99" delta="1"] `+"\n")
	})

	It("builds hostname from org, space, and app name tags", func() {
		logEnv := buildLogEnvelope("MY TASK", "2", "just a test", loggregator_v2.Log_ERR)
		logEnv.Tags["organization_name"] = "some-org"
		logEnv.Tags["space_name"] = "some-space"
		logEnv.Tags["app_name"] = "some-app"

		receivedMsgs, _ := c.ToRFC5424(logEnv, "test-hostname")
		expectConversion(receivedMsgs, `<11>1 1970-01-01T00:00:00.012345+00:00 some-org.some-space.some-app test-app-id [MY-TASK/2] - [tags@47450 app_name="some-app" organization_name="some-org" source_type="MY TASK" space_name="some-space"] just a test`+"\n")
	})

	It("builds hostname from org, space, and app name tags and sanitizes the hostname", func() {
		logEnv := buildLogEnvelope("MY TASK", "2", "just a test", loggregator_v2.Log_ERR)
		logEnv.Tags["organization_name"] = "some_org"
		logEnv.Tags["space_name"] = "some space"
		logEnv.Tags["app_name"] = "some_app--"

		receivedMsgs, _ := c.ToRFC5424(logEnv, "test-hostname")
		expectConversion(receivedMsgs, `<11>1 1970-01-01T00:00:00.012345+00:00 someorg.some-space.someapp test-app-id [MY-TASK/2] - [tags@47450 app_name="some_app--" organization_name="some_org" source_type="MY TASK" space_name="some space"] just a test`+"\n")
	})

	It("sanitizes the procid field", func() {
		logEnv := buildLogEnvelope("MY TASK", "2", "just a test", loggregator_v2.Log_ERR)
		logEnv.Tags["source_type"] = "TASK/こんにちは"

		receivedMsgs, err := c.ToRFC5424(logEnv, "test-hostname")
		Expect(err).ToNot(HaveOccurred())
		expectConversion(receivedMsgs, `<11>1 1970-01-01T00:00:00.012345+00:00 test-hostname test-app-id [TASK//2] - [tags@47450 source_type="TASK/こんにちは"] just a test`+"\n")
	})

	It("truncates hostname from tags if longer than 255 characters", func() {
		logEnv := buildLogEnvelope("MY TASK", "2", "just a test", loggregator_v2.Log_ERR)
		logEnv.Tags["organization_name"] = strings.Repeat("a", 100)
		logEnv.Tags["space_name"] = strings.Repeat("b", 100)
		logEnv.Tags["app_name"] = strings.Repeat("c", 100)

		receivedMsgs, _ := c.ToRFC5424(logEnv, "test-hostname")
		expectedMsg := fmt.Sprintf(`<11>1 1970-01-01T00:00:00.012345+00:00 %s.%s.%s test-app-id [MY-TASK/2] - [tags@47450 app_name="%s" organization_name="%s" source_type="MY TASK" space_name="%s"] just a test`,
			strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), logEnv.Tags["app_name"], logEnv.Tags["organization_name"], logEnv.Tags["space_name"])
		expectConversion(receivedMsgs, expectedMsg+"\n")
	})

	It("truncates hostname if is longer than 255", func() {
		env := buildLogEnvelope("MY TASK", "2", "just a test", loggregator_v2.Log_OUT)
		receivedMsgs, err := c.ToRFC5424(env, strings.Repeat("A", 300))
		Expect(err).ToNot(HaveOccurred())
		expectedMsg := fmt.Sprintf(`<14>1 1970-01-01T00:00:00.012345+00:00 %s test-app-id [MY-TASK/2] - [tags@47450 source_type="MY TASK"] just a test`, strings.Repeat("A", 255))
		expectConversion(receivedMsgs, expectedMsg+"\n")
	})

	It("truncates app_name if is longer than 48", func() {
		env := buildLogEnvelope("MY TASK", "2", "just a test", loggregator_v2.Log_OUT)
		env.SourceId = strings.Repeat("A", 300)
		receivedMsgs, err := c.ToRFC5424(env, "host")
		Expect(err).ToNot(HaveOccurred())
		expectedMsg := fmt.Sprintf(`<14>1 1970-01-01T00:00:00.012345+00:00 host %s [MY-TASK/2] - [tags@47450 source_type="MY TASK"] just a test`, strings.Repeat("A", 48))
		expectConversion(receivedMsgs, expectedMsg+"\n")
	})

	When("sourceType > 128 and index empty", func() {
		It("truncates sourceType when index is empty", func() {
			taskName := strings.Repeat("A", 128)
			index := ""
			expectedRenderedProcID := taskName[:128]

			env := buildLogEnvelope(taskName, index, "just a test", loggregator_v2.Log_OUT)

			receivedMsgs, err := c.ToRFC5424(env, "host")
			Expect(err).ToNot(HaveOccurred())
			expectedMsg := fmt.Sprintf(`<14>1 1970-01-01T00:00:00.012345+00:00 host test-app-id %s - [tags@47450 source_type="%s"] just a test`, expectedRenderedProcID, taskName)
			expectConversion(receivedMsgs, expectedMsg+"\n")
		})
	})
	When("sourceType > 128 and index > 128", func() {
		It("truncates sourceType and index", func() {
			taskName := strings.Repeat("A", 129)
			index := strings.Repeat("B", 129)
			expectedRenderedProcID := fmt.Sprintf("[%s/%s]", taskName[:64], index[:61])
			Expect(expectedRenderedProcID).To(HaveLen(128))

			env := buildLogEnvelope(taskName, index, "just a test", loggregator_v2.Log_OUT)

			receivedMsgs, err := c.ToRFC5424(env, "host")
			Expect(err).ToNot(HaveOccurred())
			expectedMsg := fmt.Sprintf(`<14>1 1970-01-01T00:00:00.012345+00:00 host test-app-id %s - [tags@47450 source_type="%s"] just a test`, expectedRenderedProcID, taskName)
			expectConversion(receivedMsgs, expectedMsg+"\n")
		})
	})
	When("len(sourceType) +len(index) + separators([/]) <= 128", func() {
		for _, inputPairLengths := range [][]int{
			{128, 0},
			{124, 1},
			{123, 2},
			{66, 59},
			{65, 60},
			{64, 61},
			{63, 62},
			{62, 63},
			{3, 122},
			{4, 121},
			{5, 120},
		} {
			It("will not truncate", func() {
				taskName := strings.Repeat("A", inputPairLengths[0])
				index := strings.Repeat("B", inputPairLengths[1])
				expectedRenderedProcID := taskName
				if inputPairLengths[1] != 0 {
					expectedRenderedProcID = fmt.Sprintf("[%s/%s]", taskName, index)
				}
				Expect(expectedRenderedProcID).To(HaveLen(128))

				env := buildLogEnvelope(taskName, index, "just a test", loggregator_v2.Log_OUT)

				receivedMsgs, err := c.ToRFC5424(env, "host")
				Expect(err).ToNot(HaveOccurred())
				expectedMsg := fmt.Sprintf(`<14>1 1970-01-01T00:00:00.012345+00:00 host test-app-id %s - [tags@47450 source_type="%s"] just a test`, expectedRenderedProcID, taskName)
				expectConversion(receivedMsgs, expectedMsg+"\n")
			})
		}
	})
	When("len(sourceType) +len(index) + separators([/]) <= 128", func() {
		for _, inputPairLengths := range [][]any{
			{128, 1, fmt.Sprintf("[%s/%s]", strings.Repeat("A", 124), "B")},
			{124, 2, fmt.Sprintf("[%s/%s]", strings.Repeat("A", 123), strings.Repeat("B", 2))},
			{123, 3, fmt.Sprintf("[%s/%s]", strings.Repeat("A", 122), strings.Repeat("B", 3))},
			{66, 60, fmt.Sprintf("[%s/%s]", strings.Repeat("A", 65), strings.Repeat("B", 60))},
			{65, 61, fmt.Sprintf("[%s/%s]", strings.Repeat("A", 64), strings.Repeat("B", 61))},
			{64, 62, fmt.Sprintf("[%s/%s]", strings.Repeat("A", 64), strings.Repeat("B", 61))}, // the additional length adds to the ratio of Instance
			{63, 64, fmt.Sprintf("[%s/%s]", strings.Repeat("A", 63), strings.Repeat("B", 62))},
			{62, 65, fmt.Sprintf("[%s/%s]", strings.Repeat("A", 62), strings.Repeat("B", 63))},
			{4, 122, fmt.Sprintf("[%s/%s]", strings.Repeat("A", 4), strings.Repeat("B", 121))},
			{5, 121, fmt.Sprintf("[%s/%s]", strings.Repeat("A", 5), strings.Repeat("B", 120))},
			{6, 120, fmt.Sprintf("[%s/%s]", strings.Repeat("A", 6), strings.Repeat("B", 119))},
			{70, 70, fmt.Sprintf("[%s/%s]", strings.Repeat("A", 63), strings.Repeat("B", 62))},
			{80, 70, fmt.Sprintf("[%s/%s]", strings.Repeat("A", 66), strings.Repeat("B", 59))},
		} {
			It("will truncate with minimal ratio'd cutoff", func() {
				taskName := strings.Repeat("A", inputPairLengths[0].(int))
				index := strings.Repeat("B", inputPairLengths[1].(int))
				expectedRenderedProcID := inputPairLengths[2].(string)

				env := buildLogEnvelope(taskName, index, "just a test", loggregator_v2.Log_OUT)

				receivedMsgs, err := c.ToRFC5424(env, "host")
				Expect(err).ToNot(HaveOccurred())
				expectedMsg := fmt.Sprintf(`<14>1 1970-01-01T00:00:00.012345+00:00 host test-app-id %s - [tags@47450 source_type="%s"] just a test`, expectedRenderedProcID, taskName)
				expectConversion(receivedMsgs, expectedMsg+"\n")
			})
		}
	})

	Describe("validation", func() {
		It("returns an error if app name includes unprintable characters", func() {
			env := buildLogEnvelope("MY TASK", "2", "just a test", 20)
			env.SourceId = "   "
			_, err := c.ToRFC5424(env, "test-hostname")
			Expect(err).To(HaveOccurred())
		})
	})
})

func expectConversion(received [][]byte, expected string) bool {
	return Expect(received).To(Equal([][]byte{[]byte(expected)}), fmt.Sprintf("\n%s\n%s", string(received[0]), expected))
}
