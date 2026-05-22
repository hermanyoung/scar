using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization.Formatters.Soap;
using System.Runtime.Serialization;
using System.Web.UI;
using Newtonsoft.Json;

public class DeserializationExamples
{
    // ruleid: csharp.lang.security.cwe-502.binary-formatter
    public object VulnerableBinaryFormatter(Stream stream)
    {
        var formatter = new BinaryFormatter();
        return formatter.Deserialize(stream);
    }

    // ruleid: csharp.lang.security.cwe-502.binary-formatter
    public object VulnerableNetDataContract(Stream stream)
    {
        var serializer = new NetDataContractSerializer();
        return serializer.Deserialize(stream);
    }

    // ruleid: csharp.lang.security.cwe-502.binary-formatter
    public object VulnerableSoapFormatter(Stream stream)
    {
        var formatter = new SoapFormatter();
        return formatter.Deserialize(stream);
    }

    // ruleid: csharp.lang.security.cwe-502.binary-formatter
    public object VulnerableLosFormatter(string input)
    {
        var formatter = new LosFormatter();
        return formatter.Deserialize(input);
    }

    // ruleid: csharp.lang.security.cwe-502.newtonsoft-typenamehandling
    public object VulnerableNewtonsoft(string json)
    {
        var settings = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.All
        };
        return JsonConvert.DeserializeObject(json, settings);
    }

    // ok: csharp.lang.security.cwe-502.binary-formatter
    public object SafeSystemTextJson(string json)
    {
        return System.Text.Json.JsonSerializer.Deserialize<MyDto>(json);
    }

    // ok: csharp.lang.security.cwe-502.newtonsoft-typenamehandling
    public object SafeNewtonsoftNone(string json)
    {
        var settings = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.None
        };
        return JsonConvert.DeserializeObject<MyDto>(json, settings);
    }
}

public class MyDto { public string Name { get; set; } }
