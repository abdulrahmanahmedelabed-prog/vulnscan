// expect: DF010
using System.Net.Http;
using Microsoft.AspNetCore.Mvc;

public class WebhookController : ControllerBase
{
    private readonly HttpClient _httpClient;

    [HttpPost("notify")]
    public async Task<IActionResult> Notify([FromForm] string endpoint)
    {
        var response = await _httpClient.PutAsync(endpoint, new StringContent("ping"));
        return Ok();
    }
}
