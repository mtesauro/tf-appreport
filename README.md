# tf-appreport

tf-appreport is an application used to create a draft AppSec report based on metrics from ThreadFix's REST API.

It has a default template built-in or a custom template can be provided as a command-line argument.

It produces a .fodt file which is a 'flattened' LibreOffice XML format which can be opened in LibreOffice, OpenOffice and probably the more recent versions of MS Office - though I've not tried MS Office yet.

The draft report will require a human to complete portions such as the impact to the app in question since my code won't know the context of the app data pulled from ThreadFix.

Comes with a money back guarentee! ; )
