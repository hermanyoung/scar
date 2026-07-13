using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace UnsafeApp
{
    public class DangerZone
    {
        public void RunCommand(string userInput)
        {
            Process.Start("cmd.exe", userInput);
        }

        public object LoadPayload(Stream stream)
        {
            var formatter = new BinaryFormatter();
            return formatter.Deserialize(stream);
        }
    }
}
