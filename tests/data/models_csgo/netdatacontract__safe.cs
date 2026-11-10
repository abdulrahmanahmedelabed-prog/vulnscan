// expect-none: DF006
using System.IO;
using System.Runtime.Serialization;
using Microsoft.AspNetCore.Mvc;

public class StateController : ControllerBase
{
    [HttpPost("state")]
    public IActionResult Restore([FromBody] string blob)
    {
        var stream = new MemoryStream(Convert.FromBase64String(blob));
        var state = new DataContractSerializer(typeof(CartState)).ReadObject(stream);
        return Ok();
    }
}
