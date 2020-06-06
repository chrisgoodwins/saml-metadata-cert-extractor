###############################################################################
#
# Script:       saml-metadata-cert-extractor.py
#
# Author:       Chris Goodwin <chrisgoodwins@gmail.com>
#
# Description:  This utility will extract certificates from a SAML metadata
#               file, format them properly in base64 format, then save them to
#               the working directory. It will extract all certificates that it
#               finds within the file. It will also automatically parse
#               multiple files specified through command line argument.
#
# Usage:        saml-metadata-cert-extractor.py <file1.xml> [<file2.xml>]...
#
# Requirements: None
#
# Python:       Version 3
#
###############################################################################


import re
import sys
import time
try:
    from OpenSSL import crypto
except ImportError:
    raise ValueError("pyopenssl support not available, please install module - run 'pip install pyopenssl'")


# Extract the certificate string
def cert_extractor(saml_metadata):
    re_pattern = r'(?:(?<=<ds:X509Certificate>)|(?<=<X509Certificate>))(?:\n|.)+?(?:(?=<\/(?:ds:)?X509Certificate>))'
    cert_list_raw = re.findall(re_pattern, saml_metadata, re.IGNORECASE)
    if cert_list_raw == []:
        time.sleep(.75)
        print("\nThere were no certificates found within standard '<X509Certificate>' XML tags\nCheck your metadata file and try again...\n\n")
        exit()
    return cert_list_raw


# Format certs properly before they are saved
def format_cert(cert):
    cert = re.sub(r'\s', '', cert)
    cert = re.sub(r'(.{76})', r'\1\n', cert)
    cert = re.sub(r'^\n*', '-----BEGIN CERTIFICATE-----\n', cert)
    cert = re.sub(r'\n*$', '\n-----END CERTIFICATE-----', cert)
    return cert


# Print cert details to screen
def print_cert(cert_string):
    cert_pem = crypto.load_certificate(crypto.FILETYPE_PEM, cert_string)
    cert_text = crypto.dump_certificate(crypto.FILETYPE_TEXT, cert_pem).decode('utf-8')
    cert_subject = re.search(r'Subject\s*:.+?(?=\n)', cert_text, re.IGNORECASE).group()
    cert_issuer = re.search(r'Issuer\s*:.+?(?=\n)', cert_text, re.IGNORECASE).group()
    cert_expiration_start = re.search(r'Not Before\s*:.+?(?=\n)', cert_text, re.IGNORECASE).group()
    cert_expiration_end = re.search(r'Not After\s*:.+?(?=\n)', cert_text, re.IGNORECASE).group()
    print(f'{cert_subject}\n{cert_issuer}\n{cert_expiration_start}\n{cert_expiration_end}\n\n')


def main():
    if len(sys.argv) < 2:
        time.sleep(.75)
        print('\nERROR: You need to specify at least one metadata file as a command argument\n\n')
        exit()
    for item in sys.argv[1:]:
        try:
            with open(item, 'r') as file:
                cert_list_raw = cert_extractor(file.read())
            print(f"\n\nCertificates found in {item}: {len(cert_list_raw)}\n\n")
            for index, cert in enumerate(cert_list_raw):
                cert = format_cert(cert)
                cert_filename = f"{item.replace('.', '_')}_{index + 1}.crt"
                with open(cert_filename, 'w') as file:
                    file.write(cert)
                    print('-' * (30 + len(cert_filename)), f"\nCert saved to current folder: {cert_filename}")
                    print('-' * (30 + len(cert_filename)))
                print_cert(cert)
            print('\n')
        except FileNotFoundError:
            time.sleep(.75)
            print(f"\nError: No such file or directory: '{item}'\n")


if __name__ == '__main__':
    main()
