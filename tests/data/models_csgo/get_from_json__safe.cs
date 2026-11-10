// expect-none: DF010
using System.Net.Http;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc;

public class WeatherController : ControllerBase
{
    private readonly HttpClient _http;

    [HttpGet("forecast")]
    public async Task<IActionResult> Forecast([FromQuery] string city)
    {
        var data = await _http.GetFromJsonAsync<Forecast>("https://api.weather.example.com/v1/forecast");
        return Ok(data);
    }
}
