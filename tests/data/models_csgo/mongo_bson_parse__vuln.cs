// expect: DF004
using MongoDB.Bson;
using MongoDB.Driver;
using Microsoft.AspNetCore.Mvc;

public class NotesController : ControllerBase
{
    private readonly IMongoCollection<BsonDocument> _notes;

    [HttpGet]
    public IActionResult Search([FromQuery] string author)
    {
        var filter = BsonDocument.Parse("{ author: '" + author + "' }");
        return Ok(_notes.Find(filter).ToList());
    }
}
