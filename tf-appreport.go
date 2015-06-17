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
	"text/template"
)

// JjQw4ej7mYoLIhkB2HAdQIPUqrcgqiDSguBYOSVwYwQo
// https://192.168.56.102/threadfix/rest

// Report data struct
type AppSecRpt struct {
	Product     string
	Environment string
	YYMM        string
	Month       string
	Day         string
	YYYY        string
	NumCrit     int
	NumHigh     int
	NumMed      int
	NumLow      int
	NumInfo     int
	IssId       int
	IssueTitle  string
	TotFind     int
	//AppId       int
	Finds []*Finding
	//Findings []Finding
}

type Finding struct {
	Id        int
	Title     string
	Desc      string
	AppId     int
	ScanId    int
	Path      string
	AttString string
	AttReq    string
	AttResp   string
}

func main() {
	// Setup a command-line flag to get the scan file to upload and parse for it
	scanPtr := flag.String("file", "a-template-file.xml", "the scan file to upload")
	// Add a --help option too
	flag.Parse()

	// check if -file was used and either set that or use the built in default
	// default will be built into the binary
	//fmt.Printf("The file to upload is %+v \n", *scanPtr)

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

	//t, err := template.ParseFiles("templates/AppSecReport.tpl")
	//fmt.Printf("Opened a template at %v\n", t)

	//os.Exit(0)

	//t, err := template.ParseFiles(*scanPtr)
	//fmt.Printf("\nError parsing the template is %+v\n\n", err)

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
		1,
		"Example Vulnerabilty title",
		2,
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
	err := t.Execute(rpt, d)
	fmt.Printf("\n\nError generating the report is %+v\n\n", err)
	rpt.Flush()
	fmt.Println("\nReport generation complete")

	// Create a client to talk to the API and set it as a global variable
	//	tfc, err := tf.CreateClient()
	tfc, _ := tf.CreateClient()
	//	if err != nil {
	//		fmt.Print(err)
	//		os.Exit(1)
	//	}
	fmt.Printf("Debug %+v\n", tfc)

	// TODO - Handle newlines for the fields which might not have values/strings
	//        from the TF API
}

//    {{with .Findings}}
//		{{range .}}
//			Finding ID: {{.Id}} <br />
//			Title: {{.Title}}<br />
//			Description: {{.Desc}}<br />
//		{{end}}
//	{{end}}
