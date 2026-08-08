using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace Theodicean.SharpAdb.Tests;

/// <summary>
/// Minimal TLS 1.3 server with mutual RSA certificate auth, standing in for adbd's pairing
/// service in loopback tests. Accepts any client certificate — the pairing protocol authenticates
/// via SPAKE2, not the TLS chain, matching real adbd's own always-succeed cert verify callback.
/// </summary>
internal sealed class FakePairingTlsServer : DefaultTlsServer
{
    private readonly AsymmetricKeyParameter _privateKey;
    private readonly byte[] _certificateDer;
    private Certificate? _certificate;

    internal FakePairingTlsServer(AsymmetricKeyParameter privateKey, byte[] certificateDer)
        : base(new BcTlsCrypto())
    {
        _privateKey = privateKey;
        _certificateDer = certificateDer;
    }

    /// <summary>Populated once <see cref="TlsServerProtocol.Accept"/> returns.</summary>
    internal byte[] ExportedKeyingMaterial { get; private set; } = [];

    protected override ProtocolVersion[] GetSupportedVersions() => [ProtocolVersion.TLSv13];

    public override void NotifyHandshakeComplete()
    {
        base.NotifyHandshakeComplete();
        // Must capture here: BC-TLS only allows exporting keying material from inside this
        // callback, not after Accept() returns (see AdbPairingTlsClient for the client-side twin
        // of this constraint).
        ExportedKeyingMaterial = m_context.ExportKeyingMaterial(
            Pairing.AdbPairing.ExportedKeyingMaterialLabel, null,
            Pairing.AdbPairing.ExportedKeyingMaterialLength);
    }

    public override TlsCredentials GetCredentials()
    {
        var certificate = _certificate ??= new Certificate(
            TlsUtilities.EmptyBytes,
            [new CertificateEntry(((BcTlsCrypto)Crypto).CreateCertificate(_certificateDer), extensions: null)]);

        return new BcDefaultTlsCredentialedSigner(
            new TlsCryptoParameters(m_context), (BcTlsCrypto)Crypto, _privateKey, certificate,
            SignatureAndHashAlgorithm.rsa_pss_rsae_sha256);
    }

    // certificateAuthorities: null (not an empty list — that trips an encoder bug in BC-TLS's
    // certificate_authorities extension) since we don't require any particular issuer.
    public override CertificateRequest GetCertificateRequest() => new(
        TlsUtilities.EmptyBytes,
        TlsUtilities.GetDefaultSupportedSignatureAlgorithms(m_context),
        null,
        null);

    public override void NotifyClientCertificate(Certificate clientCertificate)
    {
        // Intentionally accept any client certificate; see class summary.
    }
}
