// expect-none: DF004
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

public class SearchModel : PageModel
{
    private readonly ShopContext _db;

    public async Task OnPostAsync(string term)
    {
        var rows = await _db.Database.ExecuteSqlRawAsync("INSERT INTO Searches (Term) VALUES ({0})", term);
    }
}
