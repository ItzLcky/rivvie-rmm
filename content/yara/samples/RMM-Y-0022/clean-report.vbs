Set fso = CreateObject("Scripting.FileSystemObject")
Set f = fso.CreateTextFile("C:\Reports\today.txt", True)
f.WriteLine Now
f.Close
