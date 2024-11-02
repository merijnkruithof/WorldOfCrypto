using Org.BouncyCastle.Math;

namespace WorldOfCrypto.DiffieHellman;

public class SharedKeyGenerator
{
    /// <summary>
    /// Calculate the shared secret between party 1 and party 2.
    /// </summary>
    /// <param name="publicKey">contains the public key of the other party.</param>
    /// <param name="privateKey">contains the private key of the entity that is calculating the secret.</param>
    /// <param name="dhParameters">contains the shared generator and modulus.</param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException"></exception>
    public BigInteger GenerateSharedSecret(BigInteger publicKey, BigInteger privateKey, DhParameters dhParameters)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(dhParameters);

        // The formula behind Diffie-Hellman key exchange works as follows:
        // 1. Each party generates a private key (e.g., Alice has 'a' and Bob has 'b').
        // 2. They compute their respective public keys: 
        //    - Alice's public key is g^a mod p.
        //    - Bob's public key is g^b mod p.
        // 3. They exchange these public keys (let's call them A and B).
        // 4. Now, each party can calculate the same shared secret key:
        //    - Alice calculates B^a mod p (using Bob's public key and her private key).
        //    - Bob calculates A^b mod p (using Alice's public key and his private key).
        // Because modular exponentiation is commutative here, both will arrive at the same value:
        // g^(ab) mod p = g^(ba) mod p. 
        // This shared secret can now be used as a key for encrypted communication.
        return publicKey.ModPow(privateKey, dhParameters.Modulus);
    }
}