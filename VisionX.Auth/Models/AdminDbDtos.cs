using System.Text.Json;

namespace VisionX.Auth.Models;

public class AdminDbTableDto
{
    public string Name { get; set; } = string.Empty;
    public List<string> PrimaryKeys { get; set; } = new();
}

public class AdminDbRowsResponseDto
{
    public string Table { get; set; } = string.Empty;
    public List<string> PrimaryKeys { get; set; } = new();
    public List<Dictionary<string, object?>> Rows { get; set; } = new();
    public int Limit { get; set; }
    public int Offset { get; set; }
}

public class AdminDbInsertRequestDto
{
    public Dictionary<string, JsonElement> Values { get; set; } = new();
}

public class AdminDbUpdateRequestDto
{
    public Dictionary<string, JsonElement> Keys { get; set; } = new();
    public Dictionary<string, JsonElement> Values { get; set; } = new();
}

public class AdminDbDeleteRequestDto
{
    public Dictionary<string, JsonElement> Keys { get; set; } = new();
}
