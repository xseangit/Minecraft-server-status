using Mc.status;
using System.Text.Json;
namespace dotnet
{
    public class mcss
    {
        public void use(Microsoft.AspNetCore.Builder.WebApplication app)
        {
            app.MapGet("mc/status/{ip}", (string ip, int? port)
               =>
            { return status(ip, port); });
        }
        public string status(string ip, int? port)
        {
            if (port == null) { port = 25565; }
            MineStat ms = new MineStat(ip, (ushort)port);
            return JsonSerializer.Serialize(ms);
        }
    }
}

