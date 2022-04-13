//  Copyright 2022 Sébastian Dejonghe
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

CertificateRequest CreateRequest(X500DistinguishedName dn, out ECDsa ecdsa)
{
    ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);

    var request = new CertificateRequest(dn, ecdsa, HashAlgorithmName.SHA384);

    return request;
}

X509Certificate2 CreateRootAuthority(X509Certificate2Collection certificates, X500DistinguishedName dn)
{
    var request = CreateRequest(dn, out var ecdsa);

    using (ecdsa)
    {
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));

        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyCertSign, false));

        var today = new DateTimeOffset((DateTime.UtcNow.Ticks / TimeSpan.TicksPerDay) * TimeSpan.TicksPerDay, TimeSpan.Zero);

        var certificate = request.CreateSelfSigned(today, today.AddYears(10));

        certificates.Add(certificate);

        return certificate;
    }
}

X509Certificate2 CreateCertificate(X509Certificate2Collection certificates, X509Certificate2 issuer, X500DistinguishedName dn, IEnumerable<X509Extension> extensions)
{
    var request = CreateRequest(dn, out var ecdsa);

    using (ecdsa)
    {
        foreach (var extension in extensions)
        {
            request.CertificateExtensions.Add(extension);
        }

        var today = new DateTimeOffset((DateTime.UtcNow.Ticks / TimeSpan.TicksPerDay) * TimeSpan.TicksPerDay, TimeSpan.Zero);

        var certificate = request.Create(issuer, today, today.AddYears(5), RandomNumberGenerator.GetBytes(8));

        var copy = certificate.CopyWithPrivateKey(ecdsa);

        certificates.Add(copy);

        return copy;
    }
}

X509Certificate2 CreateWebServerCertificate(X509Certificate2Collection certificates, X509Certificate2 issuer, X500DistinguishedName dn)
{
    var builder = new SubjectAlternativeNameBuilder();
    builder.AddDnsName("localhost");
    builder.AddIpAddress(IPAddress.Any);
    builder.AddIpAddress(IPAddress.Loopback);
    builder.AddIpAddress(IPAddress.IPv6Any);
    builder.AddIpAddress(IPAddress.IPv6Loopback);

    return CreateCertificate(certificates, issuer, dn, new X509Extension[] {
        new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyAgreement | X509KeyUsageFlags.KeyEncipherment, true),
        new X509EnhancedKeyUsageExtension(new OidCollection{ new Oid("1.3.6.1.5.5.7.3.1") }, true),
        builder.Build()
        });
}

X509Certificate2 CreateWebClientCertificate(X509Certificate2Collection certificates, X509Certificate2 issuer, X500DistinguishedName dn)
{
    return CreateCertificate(certificates, issuer, dn, new X509Extension[] {
        new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyAgreement, true),
        new X509EnhancedKeyUsageExtension(new OidCollection{ new Oid("1.3.6.1.5.5.7.3.2") }, true)
        });
}

X509Certificate2 CreateSigningCertificate(X509Certificate2Collection certificates, X509Certificate2 issuer, X500DistinguishedName dn)
{
    return CreateCertificate(certificates, issuer, dn, new X509Extension[] {
        new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyAgreement | X509KeyUsageFlags.DataEncipherment, true)
        });
}

void ExportCertificateChainWithPrivateKeyToPEM(X509Certificate2Collection certificates, X509Certificate2 certificate, string path)
{
    using var writer = new StreamWriter(path);

    writer.WriteLine(PemEncoding.Write("CERTIFICATE", certificate.RawData));

    X509Certificate2? current = certificate;

    var issuer = certificate.Issuer;

    while (!current.Issuer.Equals(current.Subject))
    {
        current = certificates.FirstOrDefault(certificate => certificate.Subject.Equals(current.Issuer));

        if (current == null)
        {
            break;
        }

        writer.WriteLine(PemEncoding.Write("CERTIFICATE", current.RawData));
    }

    var privateKey = certificate.GetECDsaPrivateKey()!;

    writer.WriteLine(PemEncoding.Write("PRIVATE KEY", privateKey.ExportPkcs8PrivateKey()));
}

void ExportPrivateKeyToPEM(ECDsa ecdsa, string path)
{
    using var writer = new StreamWriter(path);

    writer.WriteLine(PemEncoding.Write("PRIVATE KEY", ecdsa.ExportPkcs8PrivateKey()));
}

void ExportPublicKeyToPEM(ECDsa ecdsa, string path)
{
    using var writer = new StreamWriter(path);

    writer.WriteLine(PemEncoding.Write("EC PUBLIC KEY", ecdsa.ExportSubjectPublicKeyInfo()));
}

void ExportCertificate(X509Certificate2Collection certificates, X509Certificate2 certificate, string fileName)
{
    File.WriteAllBytes($"{fileName}.p12", certificate.Export(X509ContentType.Pkcs12, "abcd"));
    ExportCertificateChainWithPrivateKeyToPEM(certificates, certificate, $"{fileName}-chain.pem");
    ExportPrivateKeyToPEM(certificate.GetECDsaPrivateKey()!, $"{fileName}.key");
    ExportPublicKeyToPEM(certificate.GetECDsaPublicKey()!, $"{fileName}.pub");
}

var certificates = new X509Certificate2Collection();

var rootAuthorityCertificate = CreateRootAuthority(certificates, new X500DistinguishedName("CN=Root Certificate Authority"));
ExportCertificate(certificates, rootAuthorityCertificate, "root-ca");

var tokenSigningCertificate = CreateSigningCertificate(certificates, rootAuthorityCertificate, new X500DistinguishedName("CN=Token Signing"));
ExportCertificate(certificates, tokenSigningCertificate, "token-signing");

var grpcServerCertificate = CreateWebServerCertificate(certificates, rootAuthorityCertificate, new X500DistinguishedName("CN=GRPC Server"));
ExportCertificate(certificates, grpcServerCertificate, "grpc-server");

var grpcClientCertificate = CreateWebClientCertificate(certificates, rootAuthorityCertificate, new X500DistinguishedName("CN=GRPC Client"));
ExportCertificate(certificates, grpcClientCertificate, "grpc-client");