using dotnet;
//using Microsoft.AspNetCore.OpenApi; 
using Microsoft.AspNetCore.HttpOverrides;
using System.Net;
//---------------
var builder = WebApplication.CreateBuilder(args);
builder.Host.UseSystemd();

builder.Services.AddCors();

builder.Services.AddHttpClient();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
//---------------
var app = builder.Build();


app.UseCors(builder => builder
 .AllowAnyOrigin()
 .AllowAnyMethod()
 .AllowAnyHeader()
);








Console.Write("Type:" + app.GetType() + "\n");
mcss mcss = new mcss();
mcss.use(app);
app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor |
    ForwardedHeaders.XForwardedProto
});
app.UseSwagger();
app.UseSwaggerUI();
//if (!app.Environment.IsDevelopment()) { app.UseHttpsRedirection();}

//-------------

app.Run();

//-------------

