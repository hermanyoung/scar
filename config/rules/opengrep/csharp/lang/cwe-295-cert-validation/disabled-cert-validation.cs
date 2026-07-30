using System.Net;
using System.Net.Http;
using System.Net.Security;

public class CertValidationExamples
{
    public void Vulnerable()
    {
        var handler = new HttpClientHandler();
        // ruleid: csharp.lang.security.cwe-295.disabled-cert-validation
        handler.ServerCertificateCustomValidationCallback = (sender, cert, chain, errors) => true;

        // ruleid: csharp.lang.security.cwe-295.disabled-cert-validation
        ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) => true;

        // ruleid: csharp.lang.security.cwe-295.disabled-cert-validation
        ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, errors) => true;
    }

    public void Safe()
    {
        // ok: csharp.lang.security.cwe-295.disabled-cert-validation
        var handler = new HttpClientHandler();
        var client = new HttpClient(handler);

        // ok: csharp.lang.security.cwe-295.disabled-cert-validation
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
    }
}
