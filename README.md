# VirusTotal for VSCode

This extension allows to send batches of IOCs to VirusTotal and mantain a local database with the values alredy processed.

### Analyze
Submit files to analyze in VT or check the hash.
![Analyze a file](https://github.com/SecSamDev/vscode-virustotal/raw/main/doc/AnalyzeVTfile.jpg)

### Analyze IOC list
This option will read the selected file line by line and queue them for analysis.
![Analyze IOC list](https://github.com/SecSamDev/vscode-virustotal/raw/main/doc/ImportIOClist.jpg)

### Analyze IOC present in text file
This option will read the selected text in the current document and queue it for analysis.
![Analyze IOC text](https://github.com/SecSamDev/vscode-virustotal/raw/main/doc/AnalyzeIOCinFile.jpg)

### Import IOC Database
We can import the database from another machine generated with this extension. 
![Import Database](https://github.com/SecSamDev/vscode-virustotal/raw/main/doc/ImportDatabase.jpg)


### Available commands

* **virustotal.analyze_data**: VirusTotal: Analyze IP/Hash/Domain
* **virustotal.analyze_iocs**: VirusTotal: Analyze IOC list file
* **virustotal.submit_file**: VirusTotal: Submit file to VirusTotal
* **virustotal.analyze_text**: VirusTotal: Analyze IOC present in text
* **virustotal.import_database**: VirusTotal: Import IOC database
