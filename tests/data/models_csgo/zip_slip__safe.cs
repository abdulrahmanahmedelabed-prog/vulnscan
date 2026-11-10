// expect-none: DF005
using System.IO;
using System.IO.Compression;

public static class Extractor
{
    public static void Extract(string zipPath, string dest)
    {
        var archive = ZipFile.OpenRead(zipPath);
        foreach (var entry in archive.Entries)
        {
            entry.ExtractToFile(Path.Combine(dest, Path.GetFileName(entry.FullName)), true);
        }
    }
}
