// License: MIT
// Source: https://github.com/passwordless-lib/fido2-net-lib/blob/master/Src/Fido2.Development/StoredCredential.cs
using Fido2NetLib.Objects;

#pragma warning disable
namespace csgo;

public class StoredCredential
{
    /// <summary>
    /// The Credential ID of the public key credential source.
    /// </summary>
    public byte[] Id { get; set; }

    /// <summary>
    /// The credential public key of the public key credential source.
    /// </summary>
    public byte[] PublicKey { get; set; }

    /// <summary>
    /// The latest value of the signature counter in the authenticator data from any ceremony using the public key credential source.
    /// </summary>
    public uint SignCount { get; set; }

    public List<byte[]> DevicePublicKeys { get; set; }

    public PublicKeyCredentialDescriptor Descriptor { get; set; }

    public byte[] UserHandle { get; set; }

    public DateTimeOffset RegDate { get; set; }

    public Guid AaGuid { get; set; }
}
#pragma warning restore