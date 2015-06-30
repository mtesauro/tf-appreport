// tf-appreport.go
// Tool to generate a report of the current vuln status of an
// app in ThreadFix
package main

import (
	"bufio"
	"flag"
	"fmt"
	tf "github.com/mtesauro/tfclient"
	"os"
	"strings"
	"text/template"
)

// 6ZR7SZ4lTU5s7WcAAYu2s2fDuimGD4WggVVTQUbGVc
// https://192.168.56.102/threadfix/rest
// Yeah, that's an API key for TF running on a VM on my laptop
// Feel free to get exercised about this.

// Report data struct
type AppSecRpt struct {
	Product     string // TF - Lookup App by ID - object/name
	Environment string // Stored in BOH - no API yet
	YYMM        string // based on date report is run
	Month       string // based on date report is run
	Day         string // based on date report is run
	YYYY        string // based on date report is run
	NumCrit     int    // TF - Lookup App by ID - object/criticalVulnCount
	NumHigh     int    // TF - Lookup App by ID - object/highVulnCount
	NumMed      int    // TF - Lookup App by ID - object/mediumVulnCount
	NumLow      int    // TF - Lookup App by ID - object/lowVulnCount
	NumInfo     int    // TF - Lookup App by ID - object/infoVulnCount
	TotFind     int    // Calculated based on Num[Severity] items above
	AppId       int    // Provided as a command-line arg initially
	Finds       []*Finding
	//Findings []Finding
}

type Finding struct {
	Id     int    // TF - VulnSearch - object/id
	Title  string // TF - VulnSearch - object/genericVulnerability/name
	Desc   string // TF - VulnSearch - object/findings/longDescription
	AppId  int    // TF - VulnSearch - object/app/id
	ScanId int    // Unknown - maybe in 2.2.8 API - need to check
	// Look and see if there's a better way to ID each finding
	Path      string // TF - VulnSearch - object/findings/surfaceLocation/path
	AttString string // TF - VulnSearch - object/findings/attackString
	AttReq    string // TF - VulnSearch - object/findings/attackRequest
	AttResp   string // TF - VulnSearch - object/findings/attackResponse
}

// Setup necessary helper, struct and fuctions to sort by severity

// Helper function to convert string to int for severity
func sevValue(s string) int {

	// Consider tolower'ing s
	switch s {
	case "Information":
		return 1
	case "Low":
		return 2
	case "Medium":
		return 3
	case "High":
		return 4
	case "Critical":
		return 5
	default:
		return 0
	}
}

// Type and functions to meet the sort interface
type BySeverity map[int]Finding

func (s BySeverity) Len() int {
	return len(s)
}
func (s BySeverity) Swap(i, j int) {
	//t := make(map[int]Finding)
	// need to correct order of these to match Finding struct
	//t[0] = Finding{s[j].Id, s[j].Title, s[j].Path, s[j].AttString, s[j].AttReq,
	//	s[j].AttResp, s[j].AppId, s[j].ScanId, s[j].Severity, s[j].SortBy}
	//s[j] = Finding{s[i].Id, s[i].Title, s[i].Path, s[i].AttString, s[i].AttReq,
	//	s[i].AttResp, s[i].AppId, s[i].ScanId, s[i].Severity, s[i].SortBy}
	//s[i] = Finding{t[0].Id, t[0].Title, t[0].Path, t[0].AttString, t[0].AttReq,
	//	t[0].AttResp, t[0].AppId, t[0].ScanId, t[0].Severity, t[0].SortBy}
}
func (s BySeverity) Less(i, j int) bool {
	//a := sevValue(s[i].Severity)
	a := sevValue("High")
	b := sevValue("Medium")
	//b := sevValue(s[j].Severity)
	return a > b
}

func printHelp() {
	fmt.Println()
	fmt.Println("tf-appreport")
	fmt.Println("  Creates a draft report from ThreadFix for the App ID provided")
	fmt.Println()
	fmt.Println("Usage of tf-appreport:")
	fmt.Println("  -app=[number] : the integer ID of an app in ThreadFix ** REQUIRED **\n")
	fmt.Println("  -file=[file name] : an template to use for report generation ** OPTIONAL **")
	fmt.Println("                      Note: A default report template is bundled into this binary\n")
	fmt.Println("Example:")
	fmt.Println("  tf-appreport -app 24 -file myCompany.tpl")
	fmt.Println()
}

func main() {
	// Setup a command-line flag to get the scan file to upload and parse for it
	scanPtr := flag.String("file", "a-template-file.xml", "the scan file to upload")
	appArg := flag.Int("app", 0, "the AppId from ThreadFix to report on")
	help := flag.Bool("help", false, "Get verbose help")
	flag.Parse()

	// Check if help was requested
	if *help {
		printHelp()
		os.Exit(0)
	}

	// Check if a valid AppId was provided and bail with help if its not
	if *appArg == 0 {
		fmt.Println("\nERROR: -app is a required command-line argument")
		printHelp()
		os.Exit(1)
	}

	// check if -file was used and either set that or use the built in default
	// default will be built into the binary
	fmt.Printf("appArg is %+v \n", *appArg)

	// Setup the template to create the report from
	t := template.New("app-rpt")

	// Try using template.new with the default template as a big string
	if *scanPtr == "a-template-file.xml" {
		// No file agrgument provided, using default report template
		fmt.Printf("No arg for file given - using default report\n")
		_, err := t.Parse(defReport)
		if err != nil {
			fmt.Printf("Error reading default template:\n  %+v\n\n", err)
		}
	} else {
		// Using the template provided in the command line
		fmt.Printf("The template to use is %+v \n", *scanPtr)
		_, err := t.ParseFiles(*scanPtr)
		if err != nil {
			fmt.Printf("Error reading default template:\n  %+v\n\n", err)
		}
	}

	fmt.Printf("Template is %+v\n", t)

	// Create a client to talk to the API
	tfc, err := tf.CreateClient()
	if err != nil {
		if strings.Contains(err.Error(), "Unable to find config file") {
			// Create a blank config
			if tf.CreateEmptyConfig() != nil {
				// Error creating blank config
				fmt.Printf("Error creating defaul config:\n\t%+v\n", err)
				os.Exit(1)
			} else {
				// Let user know we created a empty config and they need to edit
				fmt.Printf("\nError: No tfclient config file found\n")
				fmt.Printf("Default config created at ./tfclient.config\n")
				fmt.Printf("Please add needed values and re-run your command\n\n")
				os.Exit(0)
			}
		}

		fmt.Print(err)
		os.Exit(1)
	}

	// Lookup provided AppID
	// func LookupAppId(c *http.Client, id int) (string, error) {
	appResp, err := tf.LookupAppId(tfc, *appArg)
	if err != nil {
		fmt.Printf("\nERROR: Problem looking up App ID provided - %v\n", *appArg)
		fmt.Printf("Error reported is:\n\t%+v\n\n", err)
		os.Exit(1)
	}

	//TODO - Bug in tfclient - if you look up a non-existent app id, it doesn't
	//       return null but instead returns:
	//       {"message":"Application lookup failed. Check your ID.",
	//        "success":false,"responseCode":-1,"object":null}

	fmt.Printf("err from lookup id is %+v\n", err)
	fmt.Printf("appResp is %+v\n", appResp)

	// Turn JSON resp into a App Struct

	os.Exit(0)

	// Mock out some data
	find1 := Finding{
		Id:        1,
		Title:     "Reflective Cross-Site Scripting (XSS)",
		Desc:      "Its a really bad thing that you totally must fix or get owned",
		AppId:     666,
		ScanId:    777,
		Path:      "/app/login.do",
		AttString: "' or '1' = '1",
		AttReq:    "",
		AttResp:   "",
	}
	find2 := Finding{
		Id:        2,
		Title:     "Secure Flag not set on cookie",
		Desc:      "Cookies are valuable and must be protected.  Cookie monster says so",
		AppId:     666,
		ScanId:    777,
		Path:      "/app/profile.php",
		AttString: "<script>alert(\"Woot\")</script>",
		AttReq: `POST /app/profile.php 
		Host: www.example.com
		Accepts: text/html
		
		phone=%3Cscript%3Ealert%28%5C%22Woot%5C%22%29%3C%2Fscript%3E`,
		AttResp: "HTTP/1.1 200 OK",
	}

	d := AppSecRpt{
		"Example App",
		"Staging",
		"14-12",
		"December",
		"15",
		"2014",
		5,
		8,
		13,
		21,
		34,
		81,
		3,
		[]*Finding{&find1, &find2},
		//[]Finding{find1, find2},
	}

	//fmt.Printf("Data for report is \n%v\n%v\n", find1, find2)
	rptF, _ := os.Create("templates/AppSecAssessmentReport-DRAFT.fodt")
	//rptF, _ := os.Create("templates/trial-report.asciidoc")
	//rptF, _ := os.Create("templates/example-report.html")
	// TODO: handle error when the report cannot be read
	rpt := bufio.NewWriter(rptF)

	//fmt.Printf("Error generating the report is%v\n\n", rpt)
	//fmt.Printf("upload JSON is %+v \n\n", upResp)
	//fmt.Printf("Data for the report is%+v\n\n", rData)
	exErr := t.Execute(rpt, d)
	fmt.Printf("\n\nError generating the report is %+v\n\n", exErr)
	rpt.Flush()
	fmt.Println("\nReport generation complete")

	// Create a client to talk to the API and set it as a global variable
	//	tfc, err := tf.CreateClient()
	//tfc, _ := tf.CreateClient()
	//	if err != nil {
	//		fmt.Print(err)
	//		os.Exit(1)
	//	}
	fmt.Printf("Debug %+v\n", tfc)

	// TODO - Handle newlines for the fields which might not have values/strings
	//        from the TF API
}

// Ideas of things to add
// - deep links to individual findings for the TF install

//    {{with .Findings}}
//		{{range .}}
//			Finding ID: {{.Id}} <br />
//			Title: {{.Title}}<br />
//			Description: {{.Desc}}<br />
//		{{end}}
//	{{end}}
