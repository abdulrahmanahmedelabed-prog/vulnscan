using System.Diagnostics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Shop.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class ProductsController : ControllerBase
    {
        private readonly ShopContext _db;

        public ProductsController(ShopContext db)
        {
            _db = db;
        }

        [HttpGet("{id}")]
        public IActionResult Get(int id, [FromHeader(Name = "X-Api-Version")] string version)
        {
            return Ok(_db.Products.Find(id));
        }

        [AllowAnonymous]
        [HttpGet("search")]
        public IActionResult Search([FromQuery] string term, string order)
        {
            var rows = _db.Products.FromSqlRaw("SELECT * FROM Products WHERE Name LIKE '%" + term + "%' ORDER BY " + order);
            return Ok(rows);
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        public IActionResult Create([FromBody] ProductDto dto)
        {
            return Ok(dto);
        }

        [HttpPost("convert")]
        public IActionResult Convert([FromForm] string file)
        {
            Process.Start("convert", file);
            return Ok();
        }
    }
}
