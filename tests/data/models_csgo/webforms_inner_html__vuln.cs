// expect: DF013
using System;
using System.Web.UI;

public partial class Welcome : Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        greeting.InnerHtml = "Hello " + Request.QueryString["name"];
    }
}
