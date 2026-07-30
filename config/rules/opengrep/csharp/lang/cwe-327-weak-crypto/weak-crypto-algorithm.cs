using System.Security.Cryptography;

public class WeakCryptoExamples
{
    public byte[] VulnerableMd5(byte[] data)
    {
        // ruleid: csharp.lang.security.cwe-327.weak-crypto-algorithm
        using var md5 = MD5.Create();
        return md5.ComputeHash(data);
    }

    public byte[] VulnerableSha1(byte[] data)
    {
        // ruleid: csharp.lang.security.cwe-327.weak-crypto-algorithm
        using var sha1 = SHA1.Create();
        return sha1.ComputeHash(data);
    }

    public ICryptoTransform VulnerableDes()
    {
        // ruleid: csharp.lang.security.cwe-327.weak-crypto-algorithm
        using var des = DES.Create();
        return des.CreateEncryptor();
    }

    public void VulnerableEcb()
    {
        using var aes = Aes.Create();
        // ruleid: csharp.lang.security.cwe-327.weak-crypto-algorithm
        aes.Mode = CipherMode.ECB;
    }

    public byte[] SafeSha256(byte[] data)
    {
        // ok: csharp.lang.security.cwe-327.weak-crypto-algorithm
        using var sha256 = SHA256.Create();
        return sha256.ComputeHash(data);
    }

    public void SafeAesGcm()
    {
        using var aes = Aes.Create();
        // ok: csharp.lang.security.cwe-327.weak-crypto-algorithm
        aes.Mode = CipherMode.CBC;
        aes.KeySize = 256;
    }
}
