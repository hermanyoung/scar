using System.Xml;

public class XxeExamples
{
    // ruleid: csharp.aspnet-core.security.cwe-611.xml-external-entity
    public XmlDocument VulnerableXmlResolver(string xml)
    {
        var doc = new XmlDocument();
        doc.XmlResolver = new XmlUrlResolver();
        doc.LoadXml(xml);
        return doc;
    }

    // ruleid: csharp.aspnet-core.security.cwe-611.xml-external-entity
    public void VulnerableDtdProcessing(string xml)
    {
        var settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Parse;
        using var reader = XmlReader.Create(new System.IO.StringReader(xml), settings);
    }

    // ok: csharp.aspnet-core.security.cwe-611.xml-external-entity
    public XmlDocument SafeNoResolver(string xml)
    {
        var doc = new XmlDocument();
        doc.XmlResolver = null;
        doc.LoadXml(xml);
        return doc;
    }
}
