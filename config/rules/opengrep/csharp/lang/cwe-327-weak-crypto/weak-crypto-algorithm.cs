using System.Security.Cryptography;

public class WeakCryptoExamples
{
    // ruleid: csharp.lang.security.cwe-327.weak-crypto-algorithm
    public byte[] VulnerableMd5(byte[] data)
    {
        using var md5 = MD5.Create();
        return md5.ComputeHash(data);
    }

    // ruleid: csharp.lang.security.cwe-327.weak-crypto-algorithm
    public byte[] VulnerableSha1(byte[] data)
    {
        using var sha1 = SHA1.Create();
        return sha1.ComputeHash(data);
    }

    // ruleid: csharp.lang.security.cwe-327.weak-crypto-algorithm
    public ICryptoTransform VulnerableDes()
    {
        using var des = DES.Create();
        return des.CreateEncryptor();
    }

    // ruleid: csharp.lang.security.cwe-327.weak-crypto-algorithm
    public void VulnerableEcb()
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
    }

    // ok: csharp.lang.security.cwe-327.weak-crypto-algorithm
    public byte[] SafeSha256(byte[] data)
    {
        using var sha256 = SHA256.Create();
        return sha256.ComputeHash(data);
    }

    // ok: csharp.lang.security.cwe-327.weak-crypto-algorithm
    public void SafeAesGcm()
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.KeySize = 256;
    }
}
