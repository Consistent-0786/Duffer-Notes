
**===Document file analysis===**

\# Simple Static file analysis
\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_



01\. -> Generate md5, sha256 hash 

$ md5sum file-name

$ sha256sum file-name

---

02\. -> Check malicious hash

$ https://virustotal.com

---

03\. -> To know meta-data of the file using \*\*exiftool\*\*

$ exiftool file-name

---

04\. -> Using \*\*strings\*\* (to look for IP-addr's, websites, domains, suspicious file locations, malicious files / code)

$ strings file-name

---

05\. -> To look for encrypted strings and tries to decrypt it using \*\*xorsearch\*\* 

$ xorsearch file-name format (http, url, etc)

---



\# Advance static file analysis (Part-1)

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_ 

****Requirements****

-> Before starting, install the oletools
 $ sudo -H pip install -U oletools
----------------------------------------------------------

01\. -> To know meta-data of the file using \*\*olemeta\*\*

$ olemeta file-name

---

02\. -> To detect for malicious characteristics like VBA macros, malicious embedded objects using \*\*oleid\*\* 

$ oleid file-name

---

03\. -> Using \*\*olevba\*\* to know the indicators of malicious VBA macros file and highlight the the characters using colors

$ olevba file-name

---



\# Advance static file analysis (Part-2)

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_



01\. -> To convert .doc file to .vba file for analysis using \*\*olevba\*\*

$ olevba file.doc > file.vba

---

02\. -> To decode / deobfuscate the .vba file using \*\*olevba\*\* for better analysis

$ olevba --deobf --reveal file.vba > file\_deobf.vba

---

03\. -> Open file\_deobf.vba with \*\*vscode\*\* for analysis 

$ vscode file\_deobf.vba

---

04\. -> Open file.vba and delete everything that is not vbscript and save the file file01.vba

$ important step 

$ reference vedio ( https://youtu.be/ym6Crrn-D2c?t=776 )

---

05\. -> Analyse and running the malicious file in an safe environment using \*\*vmonkey\*\*

$ vmonkey file01.vba

---

\# Sandbox analysis 

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

1. -> Go to websites like Hybrid analysis, virustotal, anyrun, joe-sandbox










