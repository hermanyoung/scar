using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using Newtonsoft.Json;
using Microsoft.AspNetCore.Mvc;

namespace CorpusApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class DeserializationController : ControllerBase
    {
        [HttpPost("binary")]
        public IActionResult DeserializeBinary()
        {
            // CWE-502: BinaryFormatter deserialization of untrusted input
            var formatter = new BinaryFormatter();
            var obj = formatter.Deserialize(Request.Body);
            return Ok(obj?.ToString());
        }

        [HttpPost("json")]
        public IActionResult DeserializeJson([FromBody] string json)
        {
            // CWE-502: Newtonsoft TypeNameHandling.All enables type instantiation
            var settings = new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.All
            };
            var obj = JsonConvert.DeserializeObject(json, settings);
            return Ok(obj?.ToString());
        }
    }
}
