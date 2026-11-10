// expect-none: DF010
using System.Net.Http;
using Microsoft.AspNetCore.Mvc;

public class PreviewController : ControllerBase
{
    private readonly HttpClient _client;

    [HttpGet("preview")]
    public async Task<IActionResult> Preview([FromQuery] string link)
    {
        var msg = new HttpRequestMessage(HttpMethod.Head, "https://cdn.example.com/health");
        await _client.SendAsync(msg);
        return Ok(link.Length);
    }
}
