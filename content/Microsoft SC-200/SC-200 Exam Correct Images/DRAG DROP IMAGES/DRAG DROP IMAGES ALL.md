- [View on ExamTopics](https://www.examtopics.com/discussions/microsoft/view/60683-exam-sc-200-topic-1-question-1-discussion/) => Based on Comments
	DeviceLogonEvents 
	| where DeviceName  in ("CFOLaptop" , "CEOLaptop" ) and  ActionType == "LogonFailed"
	| summarize  LogonFailures=count() by DeviceName , LogonType

![[Pasted image 20260310202205.png]]

---

- [View on ExamTopics](https://www.examtopics.com/discussions/microsoft/view/81559-exam-sc-200-topic-2-question-31-discussion/) => Based on Comments
	1) Create logic app
	2) Add workflow automation (specifies action - send email)
	3) Trigger logic app (creates alert->workflow automation activates -> sends email)

![[Pasted image 20260310202753.png]]

---

- 
[View on ExamTopics](https://www.examtopics.com/discussions/microsoft/view/82109-exam-sc-200-topic-3-question-40-discussion/) => Based on Comments
	1. From the details pane of the incident, select Investigate.
	2. From the Investigation blade, select the entity that represents VM1.
	3. From the Investigation blade, select Insights

![[Pasted image 20260310203027.png]]

---

- [View on ExamTopics](https://www.examtopics.com/discussions/microsoft/view/120331-exam-sc-200-topic-3-question-84-discussion/) => Based on Comments
	1. For Sentinel1, configure the Microsoft defender for identity connector.
	2. To the AD DS Domain, deploy Microsoft Defender for Identity.
	3. For Sentinel1, enable UEBA.

![[Pasted image 20260310203446.png]]

---

- [View on ExamTopics](https://www.examtopics.com/discussions/microsoft/view/137720-exam-sc-200-topic-6-question-1-discussion/) => Based on Comments
	Connect-IPPSSession
	New-ComplianceSearch
	Start-ComplianceSearch

![[Pasted image 20260310204352.png]]

---

- [View on ExamTopics](https://www.examtopics.com/discussions/microsoft/view/157460-exam-sc-200-topic-6-question-34-discussion/) => Based on Comments
	Navigate to the device page> 
	collect investigation package>
	from the action center, invoke an action>
	extract the content of the zip file

![[Pasted image 20260310205336.png]]

---

- [View on ExamTopics](https://www.examtopics.com/discussions/microsoft/view/53474-exam-sc-200-topic-2-question-9-discussion/) => Based on AI + Comments
	1 Enable Security Health Analytics
	2 Enable the GCP Security Command Center API
	3 Create a dedicated service account and a private key 
	4 Configure the GCP Security Command Center
	5 From Azure Security Center, add cloud connectors

![[Pasted image 20260311162640.png]]

---

- [View on ExamTopics](https://www.examtopics.com/discussions/microsoft/view/63611-exam-sc-200-topic-5-question-3-discussion/) => The IMAGE is NOT Correct
	I took the exam today and it only asked me for 3 actions.
	I picked -
	1). Create an instance of MSiD
	2). Provide domain admin creds
	3). install the sensor on DC1

![[Pasted image 20260311163523.png]]

---

- [View on ExamTopics](https://www.examtopics.com/discussions/microsoft/view/145984-exam-sc-200-topic-5-question-10-discussion/) => Based on AI
	Call all the ProcessCreate parsers: _Im_ProcessCreate
	Standardize	fields to the Process schema: vimProcessCreate

![[Pasted image 20260311164005.png]]

---

- https://www.examtopics.com/discussions/microsoft/view/304835-exam-sc-200-topic-5-question-29-discussion/ => Based on Self 
	From the Microsoft Defender XDR settings, assign a device tag.
	From Advanced Features -> Turn on Deception
	From Endpoints settings, create an advanced lure

![[Pasted image 20260311164605.png]]

---

- https://www.examtopics.com/discussions/microsoft/view/315335-exam-sc-200-topic-6-question-45-discussion/
	From the Microsoft Defender XDR portal, select Copilot
	Enter the four prompts and gather the required information about a sample incident
	Create the promptbook
	Select the prompts to include in the promptbook

![[Pasted image 20260311165001.png]]

---

- [View on ExamTopics](https://www.examtopics.com/discussions/microsoft/view/315336-exam-sc-200-topic-6-question-46-discussion/) => Based on Comments , i am 100% sure

 	From the Microsoft Defender XDR portal, select Advanced features.
 	From the Microsoft Defender XDR portal, upload Script1.ps1 to the library.
	During the live response session, run the putfile command

![[Pasted image 20260311165356.png]]

---

- [View on ExamTopics](https://www.examtopics.com/discussions/microsoft/view/302600-exam-sc-200-topic-7-question-28-discussion/) => Based on AI but i think its correct 100%

From Content hub, install the Microsoft Entra ID solution.

From Workbooks, select Microsoft Entra ID Audit logs and then select View Template.

From Workbooks, select Microsoft Entra ID Audit logs and then select Save

![[Pasted image 20260311195925.png]]

---
