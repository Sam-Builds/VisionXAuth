using System.Data.Common;
using System.Globalization;
using System.Text.Json;
using VisionX.Auth.Data;
using VisionX.Auth.Models;
using Microsoft.EntityFrameworkCore;

namespace VisionX.Auth.Services;

public sealed class AdminDbService
{
    private static readonly HashSet<string> AllowedTables = new(StringComparer.OrdinalIgnoreCase)
    {
        "AspNetUsers",
        "AspNetRoles",
        "AspNetUserRoles",
        "AspNetUserClaims",
        "AspNetUserLogins",
        "AspNetUserTokens",
        "AspNetRoleClaims",
        "Sessions",
        "OtpChallenges",
        "AppConfigs",
        "OutboxMessages"
    };

    private readonly AuthDbContext _dbContext;

    public AdminDbService(AuthDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<List<AdminDbTableDto>> GetTablesAsync()
    {
        var rows = new List<AdminDbTableDto>();
        var connection = _dbContext.Database.GetDbConnection();
        await EnsureOpenAsync(connection);

        foreach (var table in AllowedTables.OrderBy(x => x))
        {
            var exists = await TableExistsAsync(connection, table);
            if (!exists)
            {
                continue;
            }

            rows.Add(new AdminDbTableDto
            {
                Name = table,
                PrimaryKeys = await GetPrimaryKeyColumnsAsync(connection, table)
            });
        }

        return rows;
    }

    public async Task<AdminDbRowsResponseDto> GetRowsAsync(string table, int limit, int offset)
    {
        ValidateTableName(table);

        var boundedLimit = Math.Clamp(limit, 1, 200);
        var boundedOffset = Math.Max(offset, 0);
        var connection = _dbContext.Database.GetDbConnection();
        await EnsureOpenAsync(connection);

        var primaryKeys = await GetPrimaryKeyColumnsAsync(connection, table);
        var orderBy = primaryKeys.Count > 0
            ? string.Join(", ", primaryKeys.Select(QuoteIdentifier))
            : "1";

        var query = $"SELECT * FROM {QuoteIdentifier(table)} ORDER BY {orderBy} LIMIT @limit OFFSET @offset";
        using var cmd = connection.CreateCommand();
        cmd.CommandText = query;

        AddParameter(cmd, "limit", boundedLimit);
        AddParameter(cmd, "offset", boundedOffset);

        var data = new List<Dictionary<string, object?>>();
        using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            for (var i = 0; i < reader.FieldCount; i++)
            {
                var name = reader.GetName(i);
                var value = reader.IsDBNull(i) ? null : reader.GetValue(i);
                row[name] = NormalizeReadValue(value);
            }

            data.Add(row);
        }

        return new AdminDbRowsResponseDto
        {
            Table = table,
            PrimaryKeys = primaryKeys,
            Rows = data,
            Limit = boundedLimit,
            Offset = boundedOffset
        };
    }

    public async Task<int> InsertRowAsync(string table, Dictionary<string, JsonElement> values)
    {
        ValidateTableName(table);
        if (values.Count == 0)
        {
            throw new InvalidOperationException("Values payload is empty.");
        }

        var connection = _dbContext.Database.GetDbConnection();
        await EnsureOpenAsync(connection);

        var columns = await GetColumnTypesAsync(connection, table);
        var filtered = values.Where(kvp => columns.ContainsKey(kvp.Key)).ToList();
        if (filtered.Count == 0)
        {
            throw new InvalidOperationException("No valid columns were provided.");
        }

        using var cmd = connection.CreateCommand();
        var columnSql = new List<string>();
        var valueSql = new List<string>();

        var index = 0;
        foreach (var (columnName, jsonValue) in filtered)
        {
            index += 1;
            var parameterName = $"p{index}";
            columnSql.Add(QuoteIdentifier(columnName));

            var dataType = columns[columnName];
            valueSql.Add(GetValueSql(parameterName, dataType));
            AddParameter(cmd, parameterName, ConvertJsonForDb(jsonValue, dataType));
        }

        cmd.CommandText = $"INSERT INTO {QuoteIdentifier(table)} ({string.Join(",", columnSql)}) VALUES ({string.Join(",", valueSql)})";
        return await cmd.ExecuteNonQueryAsync();
    }

    public async Task<int> UpdateRowAsync(string table, Dictionary<string, JsonElement> keys, Dictionary<string, JsonElement> values)
    {
        ValidateTableName(table);
        if (values.Count == 0)
        {
            throw new InvalidOperationException("Values payload is empty.");
        }

        var connection = _dbContext.Database.GetDbConnection();
        await EnsureOpenAsync(connection);

        var columns = await GetColumnTypesAsync(connection, table);
        var primaryKeys = await GetPrimaryKeyColumnsAsync(connection, table);
        if (primaryKeys.Count == 0)
        {
            throw new InvalidOperationException("Table has no primary key metadata.");
        }

        foreach (var keyColumn in primaryKeys)
        {
            if (!keys.ContainsKey(keyColumn))
            {
                throw new InvalidOperationException($"Missing primary key value: {keyColumn}");
            }
        }

        using var cmd = connection.CreateCommand();
        var setClauses = new List<string>();
        var whereClauses = new List<string>();
        var index = 0;

        foreach (var (columnName, jsonValue) in values.Where(kvp => columns.ContainsKey(kvp.Key)))
        {
            index += 1;
            var parameterName = $"p{index}";
            var dataType = columns[columnName];
            setClauses.Add($"{QuoteIdentifier(columnName)} = {GetValueSql(parameterName, dataType)}");
            AddParameter(cmd, parameterName, ConvertJsonForDb(jsonValue, dataType));
        }

        if (setClauses.Count == 0)
        {
            throw new InvalidOperationException("No valid updatable columns were provided.");
        }

        foreach (var keyColumn in primaryKeys)
        {
            index += 1;
            var parameterName = $"p{index}";
            var dataType = columns[keyColumn];
            whereClauses.Add($"{QuoteIdentifier(keyColumn)} = {GetValueSql(parameterName, dataType)}");
            AddParameter(cmd, parameterName, ConvertJsonForDb(keys[keyColumn], dataType));
        }

        cmd.CommandText = $"UPDATE {QuoteIdentifier(table)} SET {string.Join(", ", setClauses)} WHERE {string.Join(" AND ", whereClauses)}";
        return await cmd.ExecuteNonQueryAsync();
    }

    public async Task<int> DeleteRowAsync(string table, Dictionary<string, JsonElement> keys)
    {
        ValidateTableName(table);

        var connection = _dbContext.Database.GetDbConnection();
        await EnsureOpenAsync(connection);

        var columns = await GetColumnTypesAsync(connection, table);
        var primaryKeys = await GetPrimaryKeyColumnsAsync(connection, table);
        if (primaryKeys.Count == 0)
        {
            throw new InvalidOperationException("Table has no primary key metadata.");
        }

        foreach (var keyColumn in primaryKeys)
        {
            if (!keys.ContainsKey(keyColumn))
            {
                throw new InvalidOperationException($"Missing primary key value: {keyColumn}");
            }
        }

        using var cmd = connection.CreateCommand();
        var whereClauses = new List<string>();
        var index = 0;

        foreach (var keyColumn in primaryKeys)
        {
            index += 1;
            var parameterName = $"p{index}";
            var dataType = columns[keyColumn];
            whereClauses.Add($"{QuoteIdentifier(keyColumn)} = {GetValueSql(parameterName, dataType)}");
            AddParameter(cmd, parameterName, ConvertJsonForDb(keys[keyColumn], dataType));
        }

        cmd.CommandText = $"DELETE FROM {QuoteIdentifier(table)} WHERE {string.Join(" AND ", whereClauses)}";
        return await cmd.ExecuteNonQueryAsync();
    }

    private static string QuoteIdentifier(string value)
    {
        return $"\"{value.Replace("\"", "\"\"")}\"";
    }

    private static void ValidateTableName(string table)
    {
        if (!AllowedTables.Contains(table))
        {
            throw new InvalidOperationException("Table is not exposed in admin DB explorer.");
        }
    }

    private static object? NormalizeReadValue(object? value)
    {
        if (value is DBNull)
        {
            return null;
        }

        if (value is DateTime dt)
        {
            return dt.ToString("O", CultureInfo.InvariantCulture);
        }

        if (value is DateTimeOffset dto)
        {
            return dto.ToString("O", CultureInfo.InvariantCulture);
        }

        if (value is byte[] bytes)
        {
            return Convert.ToBase64String(bytes);
        }

        return value;
    }

    private static string GetValueSql(string parameterName, string dataType)
    {
        return dataType switch
        {
            "json" => $"CAST(@{parameterName} AS json)",
            "jsonb" => $"CAST(@{parameterName} AS jsonb)",
            _ => $"@{parameterName}"
        };
    }

    private static object? ConvertJsonForDb(JsonElement value, string dataType)
    {
        if (value.ValueKind == JsonValueKind.Null)
        {
            return DBNull.Value;
        }

        return dataType switch
        {
            "boolean" => value.GetBoolean(),
            "integer" => value.GetInt32(),
            "bigint" => value.GetInt64(),
            "uuid" => value.ValueKind == JsonValueKind.String
                ? Guid.Parse(value.GetString() ?? string.Empty)
                : Guid.Parse(value.GetRawText()),
            "timestamp without time zone" => value.ValueKind == JsonValueKind.String
                ? DateTime.Parse(value.GetString() ?? string.Empty, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind)
                : DateTime.Parse(value.GetRawText(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
            "timestamp with time zone" => value.ValueKind == JsonValueKind.String
                ? DateTimeOffset.Parse(value.GetString() ?? string.Empty, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind)
                : DateTimeOffset.Parse(value.GetRawText(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
            "json" or "jsonb" => value.GetRawText(),
            _ => value.ValueKind switch
            {
                JsonValueKind.String => value.GetString(),
                JsonValueKind.Number when value.TryGetInt64(out var i64) => i64,
                JsonValueKind.Number when value.TryGetDecimal(out var dec) => dec,
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                _ => value.GetRawText()
            }
        };
    }

    private static void AddParameter(DbCommand command, string name, object? value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value ?? DBNull.Value;
        command.Parameters.Add(parameter);
    }

    private static async Task EnsureOpenAsync(DbConnection connection)
    {
        if (connection.State != System.Data.ConnectionState.Open)
        {
            await connection.OpenAsync();
        }
    }

    private static async Task<bool> TableExistsAsync(DbConnection connection, string table)
    {
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = @table)";
        AddParameter(cmd, "table", table);
        var result = await cmd.ExecuteScalarAsync();
        return result is bool exists && exists;
    }

    private static async Task<List<string>> GetPrimaryKeyColumnsAsync(DbConnection connection, string table)
    {
        using var cmd = connection.CreateCommand();
        cmd.CommandText = @"
SELECT kcu.column_name
FROM information_schema.table_constraints tc
JOIN information_schema.key_column_usage kcu
  ON tc.constraint_name = kcu.constraint_name
  AND tc.table_schema = kcu.table_schema
WHERE tc.constraint_type = 'PRIMARY KEY'
  AND tc.table_schema = 'public'
  AND tc.table_name = @table
ORDER BY kcu.ordinal_position";
        AddParameter(cmd, "table", table);

        var columns = new List<string>();
        using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            columns.Add(reader.GetString(0));
        }

        return columns;
    }

    private static async Task<Dictionary<string, string>> GetColumnTypesAsync(DbConnection connection, string table)
    {
        using var cmd = connection.CreateCommand();
        cmd.CommandText = @"
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_schema = 'public'
  AND table_name = @table";
        AddParameter(cmd, "table", table);

        var output = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            output[reader.GetString(0)] = reader.GetString(1);
        }

        return output;
    }
}
