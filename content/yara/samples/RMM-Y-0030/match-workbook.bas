Private Sub Workbook_Open()
    CreateObject("WScript.Shell").Run "cmd /c calc"
End Sub
