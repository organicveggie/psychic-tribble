package testutils

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

const execTestExitCodeKey = "EXEC_HELPER_EXIT_CODE"
const execTestStdOutputKey = "EXEC_HELPER_STDOUT"
const execTestStdErrorKey = "EXEC_HELPER_STDERR"

type ExecCmdTestResult struct {
	command  string
	exitCode int
	stdOut   string
	stdErr   string
}

func MakeResult(stdOut, stdErr string, exitCode int, command ...string) ExecCmdTestResult {
	fullCommand := strings.Join(command, " ")
	return ExecCmdTestResult{
		stdOut:   stdOut,
		stdErr:   stdErr,
		exitCode: exitCode,
		command:  fullCommand,
	}
}

// ExecTestHelper provides a way to test code that uses exec.Command by providing a mockable
// function that replaces the real exec.Command function during the test.
// Usage:
//  - Create a test function starting with the prefix "Test" such as
// 	  'func TestHelperProcess(t *testing.T)'. This function must contain a call to
//    'testutils.RunTestExecCmd()'.
//
//    func TestHelperProcess(t *testing.T) {
//      testutils.RunTestExecCmd()
//    }
//
//  - Create a ExecCmdTestHelper instance using NewExecCmdTestHelper and pass in the name of the
//    test function created.
//  - For each command that you want to mock, call "AddExecResult" on the ExecCmdTestHelper instance.
//	- The code which calls exec.Command must use a variable which holds the "exec.Command" function
//    as this variable must be replaced in the test file with the ExecCmdTestHelper's ExecCommand
//    function so that it can mock the result. For example, in your code under test you should have
//    a variable such as var myexec = exec.Command, then where you would normally use exec.Command
//    you would use myexec instead. In your test file you would set myexec to the
//    ExecCmdTestHelper's ExecuteCommand function.
type ExecCmdTestHelper struct {
	testResults        map[string][]ExecCmdTestResult
	testHelperFuncName string
}

// NewExecCmdTestHelper creates a new ExecCmdTestHelper instance which will run the test function
// with the name specified by testHelperFuncName when the command is executed in order to mock the
// command's response.
func NewExecCmdTestHelper(testHelperFuncName string) *ExecCmdTestHelper {
	return &ExecCmdTestHelper{
		testResults:        make(map[string][]ExecCmdTestResult),
		testHelperFuncName: testHelperFuncName,
	}
}

// AddResult adds a mock response for the command given where the command stdout will contain
// the output string and the process will exit with the exit code given.
func (e *ExecCmdTestHelper) AddResult(stdOut, stdErr string, exitCode int, command ...string) {
	result := MakeResult(stdOut, stdErr, exitCode, command...)
	e.AddExecResult(result)
}

// AddExecResult adds a mock response.
func (e *ExecCmdTestHelper) AddExecResult(result ExecCmdTestResult) {
	base64Command := base64.StdEncoding.EncodeToString([]byte(result.command))

	if e.testResults[base64Command] == nil {
		e.testResults[base64Command] = make([]ExecCmdTestResult, 0)
	}

	e.testResults[base64Command] = append(e.testResults[base64Command], result)
}

// ExecCommand is the stub for the real exec.Command function. This is called in place of
// exec.Command. Ensure you set the var back to exec.Command once your test is complete.
func (m *ExecCmdTestHelper) ExecCommand(command string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=" + m.testHelperFuncName, "--", command}
	cs = append(cs, args...)
	cmd := exec.Command(os.Args[0], cs...)

	fullCommand := command

	if len(args) > 0 {
		fullCommand = command + " " + strings.Join(args, " ")
	}

	base64Command := base64.StdEncoding.EncodeToString([]byte(fullCommand))

	if len(m.testResults[base64Command]) == 0 {
		fmt.Println("No result was setup for command: ", fullCommand)
		return nil
	}

	// Retrieve next result
	mockResults := m.testResults[base64Command][0]

	// Remove current result so that next time it will use next result that was setup. If no next
	// result, re-use same result.
	if len(m.testResults[base64Command]) > 1 {
		m.testResults[base64Command] = m.testResults[base64Command][1:]
	}

	stdout := execTestStdOutputKey + "=" + mockResults.stdOut
	stderr := execTestStdErrorKey + "=" + mockResults.stdErr
	exitCode := execTestExitCodeKey + "=" + strconv.FormatInt(int64(mockResults.exitCode), 10)

	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1", stdout, stderr, exitCode}

	return cmd
}

// Execute will simulate the execution of a command by returning a mocked response which includes
// output to stdout, stderr and a specific exit code.
func RunTestExecCmd() {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}

	stdout := os.Getenv(execTestStdOutputKey)
	stderr := os.Getenv(execTestStdErrorKey)
	exitCode, err := strconv.ParseInt(os.Getenv(execTestExitCodeKey), 10, 64)

	if err != nil {
		os.Exit(1)
	}

	fmt.Fprint(os.Stdout, stdout)
	fmt.Fprint(os.Stderr, stderr)

	os.Exit(int(exitCode))
}
