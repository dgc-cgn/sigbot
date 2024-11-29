# Let's Sign and Verify

Still relying on unverified pdfs and screenshots as proofs? Let's fix that!

Let's build a program to enable the widescale adoption of digital signing and verification of documents on the internet. And let's use technology that you already have! 

![Logo](./assets/SignVerify-logo.png)


This program implements [DEC-03](https://github.com/dgc-cgn/DEC/blob/main/challenges/dec-03.md) and is named after the inspirational success of [Let's Encrypt](https://letsencrypt.org/), a free service provided by the [Internet Security Research Group (ISRG)](https://www.abetterinternet.org/). This program was originally entitled **Domain Name Signature Provider (DNSP) Program** but we'll use the friendlier title of **Let's Sign and Verify**.

The **sigbot** utility is inspired by [certbot](https://github.com/certbot), a utility built by the [Electron Frontier Foundation](https://www.eff.org/) to make it easy to deploy Let's Encrypt certificates. The vision for sigbot is to enable a Let's Encrypt certificate issued to a website to digitally sign and verify authoritative documents. The main area of focus is digitally signing and verifying PDF documents because PDFs are the most popular digital and printable formats for authoritative documents. Unfortunately, despite their authoritative nature, they are still hard to digitally sign and even harder to verify on a global basis.

If we achieve our goal, anyone will be able to verify the authenticity of a digitally signed PDF simply by retrieving the public key of the website owner has claimed to have signed the document. It will become just as easy a secure `https` connection. And no changes are required on the website!

If you wish to participate please contact [info@dgc-cgn.org](mailto:info@dgc-cgn.org). More details are below.
For every website domain name that has been issued a TLS certificate, the website owner can digitally sign for verification purposes any PDF document using the same public key of already issued website TLS certificate. 



# sigbot

Currently in development, Signature Bot for Let's Sign and Verify

Setup instructions are [here](SETUP.MD)
