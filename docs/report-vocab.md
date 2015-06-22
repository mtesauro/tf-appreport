##tf-appreport vocab list

###Vuln counts

{{.NumCrit}} - number of critical findings  
{{.NumHigh}} - number of high risk findings  
{{.NumMed}} - number of medium risk findings  
{{.NumLow}} - number of low risk findings  
{{.NumInfo}} - number of info risk findings  
{{.TotFind}} - total number of findings of all risk levels

{{.Product}} - name of the application in TF  
{{.AppId}} - the numeric ID of the app in TF  
{{.Month}} - Month as a string like "May"  
{{.Day}}  - Day of the month like 12  
{{.YYYY}} - Year like 2015  
{{.Environment}} - NOT YET SET

##Finding data
{{.Id}} - the numeric ID of the finding for a scan in TF  
{{.Title}} - the finding title from TF  
{{.Severity}} - the severity of the current finding - string like "Critical"  
{{.Path}} - the path for the current finding   
{{.AttString}} - the attack string in the current finding  
{{.AttReq}} - the attack request in the current findings  
{{.AttResp}} - the attack response in the current finding

###Only for Upload report generation - may end up being a separate program
{{.OrigCrit}} - number of critical findings before the upload  
{{.OrigHigh}} - number of high risk findings before the upload  
{{.OrigMed}} - number of medium risk findings before the upload  
{{.OrigLow}} - number of low risk findings before the upload  
{{.OrigInfo}} - number of info risk findings before the upload  

{{.ScanTotal}} - Total issues for the uploaded scan  
{{.ScanId}} - the numeric ID of the uploaded scan in TF  
{{.Scanner}} - the scanner type used for the upload


###Iterating through findings

Start with:

```
{{with .Finds}}{{range .}}

  [stuff here]

{{end}}{{end}}
```