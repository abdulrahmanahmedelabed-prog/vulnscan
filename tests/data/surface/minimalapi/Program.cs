using System.IO;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/files/{name}", (string name) => Results.File(File.ReadAllBytes("/srv/files/" + name)));

app.MapPost("/todos", ([FromBody] Todo todo, TodoDb db) =>
{
    db.Add(todo);
    return Results.Ok(todo);
}).RequireAuthorization();

var admin = app.MapGroup("/admin").RequireAuthorization("AdminOnly");
admin.MapDelete("/todos/{id}", (int id, TodoDb db) => db.Remove(id));
admin.MapGet("/ping", Handlers.Ping).AllowAnonymous();

app.Run();

public static class Handlers
{
    public static IResult Ping(string host)
    {
        System.Diagnostics.Process.Start("ping", host);
        return Results.Ok();
    }
}
