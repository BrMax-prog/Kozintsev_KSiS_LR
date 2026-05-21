using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();


string storageRoot = "D:\\KSiS\\_STORAGE_";
if (!Directory.Exists(storageRoot)) Directory.CreateDirectory(storageRoot);

app.MapGet("/{*filePath}", (string? filePath) =>
{
    string fullPath = GetFullPath(storageRoot, filePath);

    if (Directory.Exists(fullPath))
    {

        var currentDir = new DirectoryInfo(fullPath);

        var items = currentDir.GetFileSystemInfos().Select(info => new StorageItem
        {
            Name = info.Name,
            Type = info is FileInfo ? "File" : "Directory",
            Children = info is DirectoryInfo d ? GetDirectoryChildren(d) : null
        }).ToList();

        return Results.Ok(items); 
    }

    if (File.Exists(fullPath))
    {
        return Results.File(fullPath, "application/octet-stream", Path.GetFileName(fullPath));
    }

    return Results.NotFound("Объект не найден");
});

app.MapPut("/{*filePath}", async (HttpRequest request, string filePath) =>
{
    if (string.IsNullOrEmpty(filePath)) return Results.BadRequest("Путь не указан");

    string fullPath = GetFullPath(storageRoot, filePath);
    string? directory = Path.GetDirectoryName(fullPath);
    if (directory != null) Directory.CreateDirectory(directory);

    using (var fileStream = new FileStream(fullPath, FileMode.Create))
    {
        await request.Body.CopyToAsync(fileStream);
    }

    return Results.Ok("Файл успешно сохранен");
});

app.MapDelete("/{*filePath}", (string filePath) =>
{
    string fullPath = GetFullPath(storageRoot, filePath);

    if (File.Exists(fullPath)) { File.Delete(fullPath); return Results.NoContent(); }
    if (Directory.Exists(fullPath)) { Directory.Delete(fullPath, true); return Results.NoContent(); }

    return Results.NotFound();
});

app.MapMethods("/{*filePath}", new[] { "HEAD" }, (HttpContext context, string filePath) =>
{
    string fullPath = GetFullPath(storageRoot, filePath);

    if (!File.Exists(fullPath)) return Results.NotFound();

    var fileInfo = new FileInfo(fullPath);
    context.Response.Headers.ContentLength = fileInfo.Length;
    context.Response.Headers.LastModified = fileInfo.LastWriteTimeUtc.ToString("R");

    return Results.Ok();
});

app.Run("http://localhost:7099");

static string GetFullPath(string root, string? relativePath)
{
    if (string.IsNullOrEmpty(relativePath)) return root;
    string cleanPath = relativePath.TrimStart('/', '\\');
    return Path.GetFullPath(Path.Combine(root, cleanPath));
}

static StorageItem GetDirectoryTree(DirectoryInfo directory)
{
    var item = new StorageItem
    {
        Name = directory.Name,
        Type = "Directory",
        Children = new List<StorageItem>()
    };

    foreach (var dir in directory.GetDirectories())
    {
        item.Children.Add(GetDirectoryTree(dir));
    }

    foreach (var file in directory.GetFiles())
    {
        item.Children.Add(new StorageItem
        {
            Name = file.Name,
            Type = "File",
        });
    }

    return item;
}

static List<StorageItem> GetDirectoryChildren(DirectoryInfo directory)
{
    var children = new List<StorageItem>();

    foreach (var info in directory.GetFileSystemInfos())
    {
        children.Add(new StorageItem
        {
            Name = info.Name,
            Type = info is FileInfo ? "File" : "Directory",
            Children = info is DirectoryInfo d ? GetDirectoryChildren(d) : null
        });
    }

    return children;
}

public class StorageItem
{
    public string Name { get; set; } = "";
    public string Type { get; set; } = ""; 
    public List<StorageItem>? Children { get; set; } 
}

