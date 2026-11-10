// expect-none: DF010
using Microsoft.AspNetCore.Mvc;

public class WebhookController : ControllerBase
{
    private readonly IWebhookRepository _repository;

    [HttpDelete("hooks/{id}")]
    public async Task<IActionResult> Remove(string id)
    {
        var removed = await _repository.DeleteAsync(id);
        var updated = await _repository.PutAsync(id, "removed");
        return Ok();
    }
}
