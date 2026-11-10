// expect-none: DF013
using System;
using System.Web;
using System.Web.UI;

public partial class Welcome : Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        greeting.InnerHtml = "Hello " + HttpUtility.HtmlEncode(Request.QueryString["name"]);
    }
}
