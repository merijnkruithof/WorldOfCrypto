using System.Numerics;
using System.Security.Cryptography;

namespace WorldOfCrypto.DiffieHellman;

public class PrivateKeyGenerator
{
    /// <summary>
    /// Generate a private key based on the Diffie-Hellman parameters.
    /// </summary>
    /// <param name="parameters"></param>
    /// <returns></returns>
    public Org.BouncyCastle.Math.BigInteger GeneratePrivateKey(DhParameters parameters)
    {
        // The private key MUST be within the range of 1..p-1, because a length larger than p - 1 can result in
        // subgroup attacks.
        var byteLength = parameters.Modulus.BitLength / 8;

        Org.BouncyCastle.Math.BigInteger privateKey;
        do
        {
            Span<byte> bytes = new byte[byteLength];
            RandomNumberGenerator.Fill(bytes);

            privateKey = new Org.BouncyCastle.Math.BigInteger(1, bytes);
        } while (privateKey.CompareTo(Org.BouncyCastle.Math.BigInteger.One) < 0 || privateKey.CompareTo(parameters.Modulus) >= 0);

        return privateKey;
    }
}