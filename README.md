# Let's Sign and Verify

## Overview

Still relying on unverified pdfs and screenshots as proofs? Let's fix that!

Let's build a program to enable the widescale adoption of digital signing and verification of PDF documents on the internet. And let's use technology that you already have! 

![Logo](./assets/SignVerify-logo.png)


This program implements [DEC-03](https://github.com/dgc-cgn/DEC/blob/main/challenges/dec-03.md) and takes after the inspirational success of [Let's Encrypt](https://letsencrypt.org/), a free service provided by the [Internet Security Research Group (ISRG)](https://www.abetterinternet.org/). This program, originally entitled **Domain Name Signature Provider (DNSP) Program** is now called **Let's Sign and Verify**.



If we achieve our goal, anyone will be able to verify the authenticity of a digitally signed PDF simply by retrieving the public key of the website owner has claimed to have signed the document. It will become just as easy a secure `https` connection. And no changes are required on the website!

If you wish to participate please contact [info@dgc-cgn.org](mailto:info@dgc-cgn.org). More details are below.
For every website domain name that has been issued a TLS certificate, the website owner can digitally sign for verification purposes any PDF document using the same public key of already issued website TLS certificate. 

## What's the Key Innovation?
The key innovation in the Let's Sign and Verify program lies in decoupling the signature validation process within a PDF document from the certificate validation embedded in the document. Unlike traditional methods that rely on a certificate authority for the chain of trust, this program introduces a novel approach: extracting the public key from the certificate embedded in the PDF and comparing it to the public key of the TLS certificate associated with the verifying domain. The chain of trust shifts from a certificate authority to the website owner, who controls the verifying domain and the private key of the TLS certificate. 

This innovative approach ensures that documents can be securely signed and verified using the existing TLS infrastructure, making the process as seamless and accessible as establishing a secure HTTPS connection. By leveraging the success of [Let's Encrypt](https://letsencrypt.org/) and the [EFF certbot](https://certbot.eff.org/) utility, **Let's Sign and Verify** aims to transform digital document verification, particularly for PDFs, into an intuitive and globally scalable solution without requiring any modifications to the verifying website.

### What About Trust?

The chain of trust in the Let's Sign and Verify program begins with a legitimate domain name certificate issued by Let's Encrypt, which is inherently trusted by major browser vendors. This foundational trust enables a website owner to extend the same level of assurance to digitally signed documents. Just as a website’s TLS certificate confirms the authenticity and integrity of the website for publishing information, the program allows the public key from that certificate to be used for verifying the authenticity of documents signed by the website owner. 

This approach effectively aligns the trust model for document verification with that of existing website trust or domain name trust, ensuring that recipients can rely on the same secure infrastructure that underpins DNS and HTTPS connections. By doing so, the program creates a seamless and universally recognized trust framework that bridges website authentication and document validation, empowering website owners to securely publish both information and authoritative digital documents.

## For a Better and More Secure Internet

This approach is not intended to replace certificate authorities but rather to complement them by providing website owners with additional options for verifying PDF documents. In many scenarios, all that is required is to confirm that a PDF document genuinely originates from a specific website. By leveraging the website’s existing TLS certificate, this method offers a straightforward, open-source, and non-proprietary solution for verifying the authenticity of signed PDFs. Instead of relying solely on a certificate authority to establish trust, this approach enables users to directly validate a document's origin through the public key associated with the owner's website. This democratizes document verification, making it more accessible and practical while maintaining a robust chain of trust rooted in the website's control of its TLS certificate.

# sigbot

The command line utility **sigbot** is currently under development. Just as **certbot** brought secure websites to everyone, the hope is that **sigbot** will bring **verifiable PDFs** to everyone.

The **sigbot** utility is inspired by [certbot](https://github.com/certbot), a utility built by the [Electron Frontier Foundation](https://www.eff.org/) to make it easy to deploy Let's Encrypt certificates. The vision for sigbot is to enable a Let's Encrypt certificate issued to a website to digitally sign and verify authoritative documents. The main area of focus is digitally signing and verifying PDF documents because PDFs are the most popular digital and printable formats for authoritative documents. Unfortunately, despite their authoritative nature, they are still hard to digitally sign and even harder to verify on a global basis.

Installation and Setup instructions (without warranty) are being developed here: [INSTALL](INSTALL.md) and [SETUP](SETUP.MD)
