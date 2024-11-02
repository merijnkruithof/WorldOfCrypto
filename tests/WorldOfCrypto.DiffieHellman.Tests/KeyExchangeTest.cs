using System.Security.Cryptography;
using Org.BouncyCastle.Security;

namespace WorldOfCrypto.DiffieHellman.Tests;

public class KeyExchangeTest
{
    [Test]
    public void TestKeyExchange()
    {
        // Arrange
        var privateKeyGenerator = new PrivateKeyGenerator();
        var sharedSecretGenerator = new SharedKeyGenerator();
        var publicKeyGenerator = new PublicKeyGenerator();
        
        // Use the default DH parameters.
        var parameters = new DhParameters();
        
        // Create a secret for Alice (party 1)
        var privateKeyAlice = privateKeyGenerator.GeneratePrivateKey(parameters);
        
        // Create a secret for Bob (party 2)
        var privateKeyBob = privateKeyGenerator.GeneratePrivateKey(parameters);
        
        // Alice will now generate her public key
        var alicesPublicKey = publicKeyGenerator.GeneratePublicKey(privateKeyAlice, parameters);
        
        // Bob wil now generate his public key
        var bobsPublicKey = publicKeyGenerator.GeneratePublicKey(privateKeyBob, parameters);

        // Now we'll generate the shared secret.
        var sharedSecretAlice = sharedSecretGenerator.GenerateSharedSecret(bobsPublicKey, privateKeyAlice, parameters);
        var sharedSecretBob = sharedSecretGenerator.GenerateSharedSecret(alicesPublicKey, privateKeyBob, parameters);
        
        Assert.That(sharedSecretBob, Is.EqualTo(sharedSecretAlice));
    }
}