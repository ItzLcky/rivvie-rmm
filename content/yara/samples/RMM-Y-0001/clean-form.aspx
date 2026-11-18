<%@ Page Language="C#" %>
<% var name = Request.Form["name"]; Response.Write(Server.HtmlEncode(name)); %>
