#!/usr/bin/env python3
# Färbt die nativen Android-System-Leisten (Statusleiste oben, Navigationsleiste
# unten) in der stilla-Hintergrundfarbe. Läuft im CI NACH `cap add android`,
# weil der android/-Ordner bei jedem Build neu erzeugt wird.
import re, sys, pathlib

RES = pathlib.Path("android/app/src/main/res/values")
BG = "#FF10151E"   # ARGB, stilla-Hintergrund (#10151e), voll deckend

colors = RES / "colors.xml"
styles = RES / "styles.xml"

def ensure_color():
    if not colors.exists():
        colors.write_text('<?xml version="1.0" encoding="utf-8"?>\n<resources>\n</resources>\n', encoding="utf-8")
    t = colors.read_text(encoding="utf-8")
    if 'name="stillaBg"' not in t:
        t = t.replace("</resources>", f'    <color name="stillaBg">{BG}</color>\n</resources>')
        colors.write_text(t, encoding="utf-8")
        print("colors.xml: stillaBg ergänzt")
    else:
        print("colors.xml: stillaBg schon vorhanden")

BAR_ITEMS = (
    '        <item name="android:statusBarColor">@color/stillaBg</item>\n'
    '        <item name="android:navigationBarColor">@color/stillaBg</item>\n'
    '        <item name="android:windowLightStatusBar">false</item>\n'
    '        <item name="android:windowLightNavigationBar">false</item>\n'
)

def patch_styles():
    if not styles.exists():
        print("styles.xml fehlt – übersprungen"); return
    t = styles.read_text(encoding="utf-8")
    # In jeden Style-Block, dessen Name "NoActionBar" enthält, die Leisten-Items
    # vor dem schließenden </style> einfügen (sofern noch nicht vorhanden).
    def repl(m):
        block = m.group(0)
        if "statusBarColor" in block:
            return block
        return block.replace("</style>", BAR_ITEMS + "    </style>")
    t2 = re.sub(r'<style\s+name="[^"]*NoActionBar[^"]*"[^>]*>.*?</style>', repl, t, flags=re.S)
    if t2 != t:
        styles.write_text(t2, encoding="utf-8")
        print("styles.xml: System-Leisten eingefärbt")
    else:
        print("styles.xml: nichts zu ändern (schon gesetzt?)")

MANIFEST = pathlib.Path("android/app/src/main/AndroidManifest.xml")
def patch_manifest():
    if not MANIFEST.exists():
        print("AndroidManifest.xml fehlt – übersprungen"); return
    t = MANIFEST.read_text(encoding="utf-8")
    perms = [
        '<uses-permission android:name="android.permission.RECORD_AUDIO" />',
        '<uses-permission android:name="android.permission.MODIFY_AUDIO_SETTINGS" />',
    ]
    add = "".join("    "+p+"\n" for p in perms if p not in t)
    if add:
        t = t.replace("<application", add+"\n    <application", 1)
        MANIFEST.write_text(t, encoding="utf-8")
        print("AndroidManifest.xml: Mikrofon-Berechtigung ergänzt")
    else:
        print("AndroidManifest.xml: Mikrofon-Berechtigung schon vorhanden")

ensure_color()
patch_styles()
patch_manifest()
print("Theme-Patch fertig.")
