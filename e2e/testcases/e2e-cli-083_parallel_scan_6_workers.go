package testcases

// E2E-CLI-083 - KICS  scan
// should perform a scan, finishing successfully and return exit code 0
func init() { //nolint
	testSample := TestCase{
		Name: "should perform a scan and finish successfully [E2E-CLI-083]",
		Args: args{
			Args: []cmdArgs{
				[]string{"scan", "-o", "/path/e2e/output",
					"--output-name", "E2E_CLI_083_RESULT",
					"-p", "\"/path/e2e/fixtures/samples/long_terraform.tf\"",
					"--parallel", "6",
				},
			},
			ExpectedResult: []ResultsValidation{
				{
					ResultsFile:    "E2E_CLI_083_RESULT",
					ResultsFormats: []string{"json"},
				},
			},
		},
		WantStatus: []int{50},
	}

	Tests = append(Tests, testSample)
}
