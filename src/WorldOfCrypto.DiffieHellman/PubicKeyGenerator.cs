using Org.BouncyCastle.Math;

namespace WorldOfCrypto.DiffieHellman;

public class PubicKeyGenerator
{
    /// <summary>
    /// Generates a public key using Diffie-Hellman parameters.
    ///
    /// The public key is derived by calculating g^secret mod p, where g is the generator and p is the modulus.
    /// This is an essential intermediate step in the Diffie-Hellman key exchange, as the other party needs this
    /// public key to calculate the shared secret.
    /// </summary>
    /// <param name="privateKey">A BigInteger representing the private key of the party generating the public key.</param>
    /// <param name="dhParameters">The Diffie-Hellman parameters, which contain the modulus and generator.</param>
    /// <returns>A BigInteger representing the public key for the given private key and DH parameters.</returns>
    public BigInteger GeneratePublicKey(BigInteger privateKey, DhParameters dhParameters)
    {
        return dhParameters.Generator.ModPow(privateKey, dhParameters.Modulus);
    }
}