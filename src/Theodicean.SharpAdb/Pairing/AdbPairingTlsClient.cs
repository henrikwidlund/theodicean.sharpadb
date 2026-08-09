using System.Security.Cryptography;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace Theodicean.SharpAdb.Pairing;

/// <summary>
/// A TLS 1.3-only client with mutual RSA certificate authentication, matching adbd's pairing
/// transport (<c>SSL_CTX_set_min/max_proto_version(TLS1_3_VERSION)</c>,
/// <c>SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT</c>). Uses BouncyCastle's pure-managed TLS
/// stack rather than <see cref="System.Net.Security.SslStream"/> because this is the only way to
/// reach the RFC 5705 exported keying material the pairing password derivation needs — .NET's
/// BCL has no public API for that (tracked at
/// <see href="https://github.com/dotnet/runtime/issues/112529"/>, unimplemented as of .NET 10).
/// The server certificate is accepted unconditionally: like adbd's own pairing client, this
/// protocol only needs to prove key possession over the connection, not chain-of-trust.
/// </summary>
internal sealed class AdbPairingTlsClient : DefaultTlsClient
{
    private readonly AsymmetricKeyParameter _privateKey;
    private readonly byte[] _certificateDer;
    private Certificate? _certificate;

    internal AdbPairingTlsClient(AsymmetricKeyParameter privateKey, byte[] certificateDer)
        : base(new BcTlsCrypto())
    {
        _privateKey = privateKey;
        _certificateDer = certificateDer;
    }

    private Certificate GetCertificate() => _certificate ??= new Certificate(
        TlsUtilities.EmptyBytes,
        [new CertificateEntry(((BcTlsCrypto)Crypto).CreateCertificate(_certificateDer), extensions: null)]);

    protected override ProtocolVersion[] GetSupportedVersions() => [ProtocolVersion.TLSv13];

    /// <summary>
    /// The RFC 5705 exported keying material ADB mixes into the SPAKE2 password. Populated once
    /// <see cref="TlsClientProtocol.Connect"/> returns.
    /// </summary>
    internal byte[] ExportedKeyingMaterial { get; private set; } = [];

    public override TlsAuthentication GetAuthentication() => new PairingAuthentication(this);

    public override void NotifyHandshakeComplete()
    {
        base.NotifyHandshakeComplete();
        // BC-TLS only allows exporting keying material from inside this callback (it asserts the
        // secret hasn't been wiped yet) — calling ExportKeyingMaterial after Connect() returns
        // throws InvalidOperationException, so the value must be captured here and cached.
        ExportedKeyingMaterial = m_context.ExportKeyingMaterial(
            AdbPairing.ExportedKeyingMaterialLabel, null, AdbPairing.ExportedKeyingMaterialLength);
    }

    /// <summary>
    /// Builds an RSA private key parameter directly from <see cref="RSAParameters"/>, avoiding any
    /// PEM round-trip or dependency on BouncyCastle's ASN.1/PEM readers.
    /// </summary>
    internal static RsaPrivateCrtKeyParameters ToBouncyCastleKey(in RSAParameters p) => new(
        ToBigInteger(p.Modulus!), ToBigInteger(p.Exponent!), ToBigInteger(p.D!),
        ToBigInteger(p.P!), ToBigInteger(p.Q!), ToBigInteger(p.DP!), ToBigInteger(p.DQ!), ToBigInteger(p.InverseQ!));

    private static BigInteger ToBigInteger(byte[] unsignedBigEndian) => new(1, unsignedBigEndian);

    private sealed class PairingAuthentication(AdbPairingTlsClient owner) : TlsAuthentication
    {
        public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
        {
            // Intentionally accept any certificate: pairing authenticates via the SPAKE2 password,
            // not the TLS certificate chain (there is no CA here — every device presents a
            // self-signed cert). This mirrors adbd's own SetCertVerifyCallback, which always
            // returns success.
        }

        public TlsCredentials GetClientCredentials(CertificateRequest certificateRequest)
        {
            var cryptoParams = new TlsCryptoParameters(owner.m_context);
            return new BcDefaultTlsCredentialedSigner(
                cryptoParams, (BcTlsCrypto)owner.Crypto, owner._privateKey, owner.GetCertificate(),
                SelectSignatureAlgorithm(certificateRequest.SupportedSignatureAlgorithms));
        }

        // Picks a scheme our RSA key can actually sign with from what the server's
        // CertificateRequest advertised, instead of assuming it offered our preferred one.
        private static SignatureAndHashAlgorithm SelectSignatureAlgorithm(
            IList<SignatureAndHashAlgorithm>? serverSupportedAlgorithms)
        {
            return serverSupportedAlgorithms
                       ?.FirstOrDefault(static a =>
                           // rsa_pss_rsae_* are TLS 1.3 "intrinsic" combined schemes (RFC 8446 §4.2.3):
                           // their SignatureAndHashAlgorithm.Hash field is HashAlgorithm.Intrinsic, not a
                           // real hash — hence matching on the ready-made static instances rather than
                           // constructing one via SignatureAndHashAlgorithm.GetInstance(sha256, ...).
                           Equals(a, SignatureAndHashAlgorithm.rsa_pss_rsae_sha256) ||
                           Equals(a, SignatureAndHashAlgorithm.rsa_pss_rsae_sha384) ||
                           Equals(a, SignatureAndHashAlgorithm.rsa_pss_rsae_sha512))
                   // TLS 1.3 mandates rsa_pss_rsae_sha256 support for any RSA certificate (RFC 8446
                   // §9.1), so this is a safe fallback if the server's list omitted it for some reason
                   // rather than an arbitrary guess.
                   ?? SignatureAndHashAlgorithm.rsa_pss_rsae_sha256;
        }
    }
}
