- [View on ExamTopics](https://www.examtopics.com/discussions/microsoft/view/60683-exam-sc-200-topic-1-question-1-discussion/) => Based on Comments
	DeviceLogonEvents 
	| where DeviceName  in ("CFOLaptop" , "CEOLaptop" ) and  ActionType == "LogonFailed"
	| summarize  LogonFailures=count() by DeviceName , LogonType

