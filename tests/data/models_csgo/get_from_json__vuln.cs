// expect: DF010
using System.Net.Http;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc;

public class WeatherController : ControllerBase
{
    private readonly HttpClient _http;

    [HttpGet("forecast")]
    public async Task<IActionResult> Forecast([FromQuery] string source)
    {
        var data = await _http.GetFromJsonAsync<Forecast>(source);
        return Ok(data);
    }
}
