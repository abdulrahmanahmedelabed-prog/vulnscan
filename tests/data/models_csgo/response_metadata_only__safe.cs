// expect-none: DF013
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;

public static class CatalogApi
{
    // response metadata ([ProducesResponseType]) says nothing about where the parameters come from:
    // `services` is resolved from DI, and the JSON helper result is not HTML
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest, "application/problem+json")]
    public static async Task<Ok<CatalogPage>> GetItemsByName(CatalogServices services, string name)
    {
        return await GetAllItems(services, name);
    }

    private static async Task<Ok<CatalogPage>> GetAllItems(CatalogServices services, string name)
    {
        var page = await services.Query(name);
        return TypedResults.Ok(page);
    }
}
