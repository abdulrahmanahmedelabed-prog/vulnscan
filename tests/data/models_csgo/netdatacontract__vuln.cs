// expect: DF006
using System.IO;
using System.Runtime.Serialization;
using Microsoft.AspNetCore.Mvc;

public class StateController : ControllerBase
{
    [HttpPost("state")]
    public IActionResult Restore([FromBody] string blob)
    {
        var stream = new MemoryStream(Convert.FromBase64String(blob));
        var state = new NetDataContractSerializer().ReadObject(stream);
        return Ok();
    }
}
