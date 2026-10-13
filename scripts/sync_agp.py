#!/usr/bin/env python3
# TODO: Verify latest AGP compatibility with the installed Gradle and Android SDK at build time.
# Risk: breaking upstream AGP updates should fail the build, not silently downgrade.
# Verification: report resolved AGP version, run assembleDebug, inspect resulting APK.
"""Select the newest final AGP from Google's official Maven metadata for this build."""
from pathlib import Path
import re
import urllib.request
import xml.etree.ElementTree as ET

url = "https://dl.google.com/dl/android/maven2/com/android/tools/build/gradle/maven-metadata.xml"
with urllib.request.urlopen(url, timeout=30) as response:
    root = ET.fromstring(response.read())
versions = [
    v.text for v in root.findall(".//version")
    if v.text and re.fullmatch(r"\d+\.\d+\.\d+", v.text)
]
assert versions, "No final AGP version available"
latest = max(versions, key=lambda value: tuple(map(int, value.split("."))))
path = Path("build.gradle.kts")
content = path.read_text()
updated, count = re.subn(
    r'(id\("com\.android\.application"\) version ")[^"]+(")',
    lambda match: match.group(1) + latest + match.group(2),
    content,
)
assert count == 1
path.write_text(updated)
print(f"Resolved AGP: {latest}")
