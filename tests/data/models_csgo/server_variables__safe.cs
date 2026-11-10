// expect-none: DF013
using System;
using System.Web;
using System.Web.UI;

public partial class Status : Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        Response.Write("<p>Referrer: " + HttpUtility.HtmlEncode(Request.ServerVariables["HTTP_REFERER"]) + "</p>");
    }
}
