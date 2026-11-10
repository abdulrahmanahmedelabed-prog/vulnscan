// expect: DF013
using System;
using System.Web.UI;

public partial class Status : Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        Response.Write("<p>Referrer: " + Request.ServerVariables["HTTP_REFERER"] + "</p>");
    }
}
