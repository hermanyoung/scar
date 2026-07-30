using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization.Formatters.Soap;
using System.Runtime.Serialization;
using System.Web.UI;
using Newtonsoft.Json;

public class DeserializationExamples
{
    public object VulnerableBinaryFormatter(Stream stream)
    {
        // ruleid: csharp.lang.security.cwe-502.binary-formatter
        var formatter = new BinaryFormatter();
        return formatter.Deserialize(stream);
    }

    public object VulnerableNetDataContract(Stream stream)
    {
        // ruleid: csharp.lang.security.cwe-502.binary-formatter
        var serializer = new NetDataContractSerializer();
        return serializer.Deserialize(stream);
    }

    public object VulnerableSoapFormatter(Stream stream)
    {
        // ruleid: csharp.lang.security.cwe-502.binary-formatter
        var formatter = new SoapFormatter();
        return formatter.Deserialize(stream);
    }

    public object VulnerableLosFormatter(string input)
    {
        // ruleid: csharp.lang.security.cwe-502.binary-formatter
        var formatter = new LosFormatter();
        return formatter.Deserialize(input);
    }

    public object VulnerableNewtonsoft(string json)
    {
        var settings = new JsonSerializerSettings
        {
            // ruleid: csharp.lang.security.cwe-502.newtonsoft-typenamehandling
            TypeNameHandling = TypeNameHandling.All
        };
        return JsonConvert.DeserializeObject(json, settings);
    }

    public object SafeSystemTextJson(string json)
    {
        // ok: csharp.lang.security.cwe-502.binary-formatter
        return System.Text.Json.JsonSerializer.Deserialize<MyDto>(json);
    }

    public object SafeNewtonsoftNone(string json)
    {
        var settings = new JsonSerializerSettings
        {
            // ok: csharp.lang.security.cwe-502.newtonsoft-typenamehandling
            TypeNameHandling = TypeNameHandling.None
        };
        return JsonConvert.DeserializeObject<MyDto>(json, settings);
    }
}

public class MyDto { public string Name { get; set; } }
