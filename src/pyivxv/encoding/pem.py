import base64
import re


def pem_to_der(data: bytes) -> bytes:
    if b"-----BEGIN" not in data:
        return data

    pem_header_re = re.compile(br"-----BEGIN ([A-Z0-9 ]+)-----")
    pem_footer_re = re.compile(br"-----END ([A-Z0-9 ]+)-----")

    header_match = pem_header_re.search(data)
    footer_match = pem_footer_re.search(data)

    if not (header_match and footer_match):
        raise ValueError("Invalid PEM: missing header or footer")

    header_type = header_match.group(1)
    footer_type = footer_match.group(1)

    if header_type != footer_type:
        raise ValueError(
            f"PEM header/footer mismatch: {header_type.decode()} vs {footer_type.decode()}"
        )

    body = data[header_match.end():footer_match.start()]
    body = b"".join(body.split())

    try:
        return base64.b64decode(body, validate=True)
    except Exception as e:
        raise ValueError("Invalid base64 in PEM body") from e
