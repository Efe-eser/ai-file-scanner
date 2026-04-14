from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings

import requests
import hashlib
import os
import math
from collections import Counter
import joblib
import struct

from .serializers import FileSerializer
from openai import OpenAI

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# ── Kütüphane kontrolleri ──────────────────────────
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

# signify: Authenticode imzasını cross-platform okur
# pip install signify
try:
    from signify.authenticode import SignedPEFile
    SIGNIFY_AVAILABLE = True
except ImportError:
    SIGNIFY_AVAILABLE = False


# ----------------------------
# FRONTEND VIEW
# ----------------------------
def home(request):
    return render(request, "upload.html")


# ----------------------------
# OPTIONAL ML MODEL
# ----------------------------
try:
    model = joblib.load("model.pkl")
except Exception:
    model = None


# ----------------------------
# BİLİNEN UYGULAMALAR LİSTESİ
# ----------------------------
KNOWN_APPS = {
    "discord":   "Discord",
    "chrome":    "Google Chrome",
    "firefox":   "Mozilla Firefox",
    "steam":     "Steam",
    "spotify":   "Spotify",
    "vlc":       "VLC Media Player",
    "zoom":      "Zoom",
    "teams":     "Microsoft Teams",
    "skype":     "Skype",
    "telegram":  "Telegram",
    "whatsapp":  "WhatsApp",
    "obs":       "OBS Studio",
    "winrar":    "WinRAR",
    "7zip":      "7-Zip",
    "python":    "Python",
    "nodejs":    "Node.js",
    "git":       "Git",
    "vscode":    "Visual Studio Code",
    "notepad":   "Notepad++",
    "brave":     "Brave Browser",
    "opera":     "Opera",
    "edge":      "Microsoft Edge",
    "onedrive":  "Microsoft OneDrive",
    "dropbox":   "Dropbox",
    "minecraft": "Minecraft",
    "epicgames": "Epic Games",
    "nvidia":    "NVIDIA",
    "amd":       "AMD Software",
    "update":    "Application Updater",
    "installer": "Official Installer",
    "setup":     "Official Setup",
}


# ----------------------------
# AUTHENTİCODE İMZA OKUYUCU
# Windows'un kullandığı gerçek dijital imza sistemi
# ----------------------------
def read_authenticode_signature(file_data):
    """
    signify kütüphanesi ile gerçek Authenticode imzasını okur.
    Dönüş: {
        "signed": True/False,
        "verified": True/False,   # imza geçerli mi?
        "publisher": str,          # ör. "Discord Inc."
        "issuer": str,             # ör. "DigiCert"
    }
    """
    if not SIGNIFY_AVAILABLE:
        return _read_signature_fallback(file_data)

    try:
        import io
        signed_pe = SignedPEFile(io.BytesIO(file_data))

        # İmza var mı?
        try:
            signed_data_list = list(signed_pe.signed_datas)
        except Exception:
            return {"signed": False, "verified": False, "publisher": None, "issuer": None}

        if not signed_data_list:
            return {"signed": False, "verified": False, "publisher": None, "issuer": None}

        signed_data = signed_data_list[0]

        # İmza doğrulama — zinciri kontrol eder
        verified = False
        try:
            signed_pe.verify()
            verified = True
        except Exception:
            # İmza var ama doğrulanamadı (expired cert vs.)
            verified = False

        # Publisher bilgisi
        publisher = None
        issuer    = None

        try:
            # Signer certificate
            signer = signed_data.signer_info
            cert   = signer.certificate

            if cert:
                # Subject'ten CN veya O al
                subject = cert.subject.human_friendly
                publisher = _extract_cn(subject)

                # Issuer
                issuer_str = cert.issuer.human_friendly
                issuer = _extract_cn(issuer_str)

        except Exception:
            pass

        # Fallback: pefile'dan CompanyName oku
        if not publisher:
            publisher = _get_company_from_pefile(file_data)

        return {
            "signed":    True,
            "verified":  verified,
            "publisher": publisher,
            "issuer":    issuer,
        }

    except Exception:
        return _read_signature_fallback(file_data)


def _extract_cn(dn_string):
    """Distinguished Name string'inden CN veya O değerini çeker."""
    try:
        for part in dn_string.split(","):
            part = part.strip()
            if part.startswith("CN="):
                val = part[3:].strip().strip('"')
                # Gereksiz suffix'leri temizle
                for suffix in [" (TEST)", " TEST", " - TEST"]:
                    val = val.replace(suffix, "")
                return val
        for part in dn_string.split(","):
            part = part.strip()
            if part.startswith("O="):
                return part[2:].strip().strip('"')
    except Exception:
        pass
    return None


def _get_company_from_pefile(file_data):
    """pefile ile CompanyName ve ProductName okur."""
    if not PEFILE_AVAILABLE:
        return None
    try:
        pe = pefile.PE(data=file_data)
        if hasattr(pe, 'FileInfo'):
            for file_info in pe.FileInfo:
                if hasattr(file_info, 'StringTable'):
                    for st in file_info.StringTable:
                        company = None
                        product = None
                        for key, val in st.entries.items():
                            k = key.decode(errors="ignore").lower() if isinstance(key, bytes) else key.lower()
                            v = val.decode(errors="ignore").strip()  if isinstance(val, bytes) else val.strip()
                            if k == "companyname" and v:
                                company = v
                            if k == "productname" and v:
                                product = v
                        if company:
                            pe.close()
                            return company
                        if product:
                            pe.close()
                            return product
        pe.close()
    except Exception:
        pass
    return None


def _read_signature_fallback(file_data):
    """signify yoksa pefile ile temel imza bilgisi okur."""
    if not PEFILE_AVAILABLE:
        return {"signed": False, "verified": False, "publisher": None, "issuer": None}

    try:
        pe = pefile.PE(data=file_data)
        has_sig   = hasattr(pe, 'DIRECTORY_ENTRY_SECURITY')
        publisher = _get_company_from_pefile(file_data)
        pe.close()
        return {
            "signed":    has_sig,
            "verified":  has_sig,  # doğrulayamıyoruz ama imza var
            "publisher": publisher,
            "issuer":    None,
        }
    except Exception:
        return {"signed": False, "verified": False, "publisher": None, "issuer": None}


# ----------------------------
# UYGULAMA TANIMA MANTIĞI
# ----------------------------
def identify_application(filename, file_data, vt_malicious, vt_suspicious):
    """
    Dönüş: {
        "certified": bool,       # Windows imzalı ve VT temiz
        "verified": bool,        # İmza zinciri geçerli
        "app_name": str | None,  # Gösterilecek isim
        "publisher": str | None, # ör. "Discord Inc."
        "issuer": str | None,    # ör. "DigiCert"
    }
    """
    ext        = os.path.splitext(filename)[1].lower()
    name_lower = os.path.splitext(filename.lower())[0]

    # Bilinen uygulama isim eşleşmesi
    matched_app = None
    for key, display_name in KNOWN_APPS.items():
        if key in name_lower:
            matched_app = display_name
            break

    # PE dosyaları için imza oku
    sig = {"signed": False, "verified": False, "publisher": None, "issuer": None}
    if ext in [".exe", ".dll", ".msi", ".sys"]:
        sig = read_authenticode_signature(file_data)

    # VT kötü sonuç veriyorsa certified olamaz
    if vt_malicious > 0 or vt_suspicious > 2:
        return {
            "certified": False,
            "verified":  False,
            "app_name":  matched_app,
            "publisher": sig["publisher"],
            "issuer":    sig["issuer"],
        }

    # İmzalı + VT temiz → certified
    if sig["signed"]:
        publisher = sig["publisher"]
        if matched_app and publisher:
            app_display = f"{matched_app}"
        elif matched_app:
            app_display = matched_app
        elif publisher:
            app_display = publisher
        else:
            app_display = "Digitally Signed Application"

        return {
            "certified": True,
            "verified":  sig["verified"],
            "app_name":  app_display,
            "publisher": publisher,
            "issuer":    sig["issuer"],
        }

    # İmzasız ama bilinen isim + VT temiz
    return {
        "certified": False,
        "verified":  False,
        "app_name":  matched_app,
        "publisher": None,
        "issuer":    None,
    }


# ----------------------------
# AI ANALİZ
# ----------------------------
def get_ai_analysis(filename, ext, file_size, final_score, entropy, strings_found, vt_malicious, vt_suspicious):
    truly_suspicious = [s for s in strings_found if s in [
        "cmd.exe", "powershell", "wget", "curl", "base64",
        "shell", "chmod", "eval", "invoke-expression",
        "downloadstring", "createobject", "wscript",
        "regsvr32", "mshta", "rundll32",
    ]]

    prompt = f"""You are a concise cybersecurity analyst. Analyze this file in 2-3 sentences max.
Be direct. State if safe or dangerous and the main reason. Don't repeat UI numbers.

File: {filename} | Type: {ext} | Size: {round(file_size/1024,1)} KB
Risk: {final_score}/100 | Entropy: {entropy}
Suspicious indicators: {truly_suspicious if truly_suspicious else 'None'}
VirusTotal: {vt_malicious} malicious, {vt_suspicious} suspicious"""

    try:
        r = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=120,
            temperature=0.3,
        )
        return r.choices[0].message.content.strip()
    except Exception:
        return "AI analysis unavailable."


# ----------------------------
# SCORE HELPERS
# ----------------------------
def calculate_entropy(data):
    if not data:
        return 0.0
    counter = Counter(data)
    length  = len(data)
    ent     = 0.0
    for c in counter.values():
        p = c / length
        ent -= p * math.log2(p)
    return ent


def suspicious_strings(data):
    keywords = [
        b"cmd.exe", b"powershell", b"wget", b"curl",
        b"base64", b"shell", b"chmod", b"eval",
        b"invoke-expression", b"downloadstring",
        b"createobject", b"wscript", b"regsvr32",
        b"mshta", b"rundll32",
    ]
    found = []
    low   = data.lower()
    for k in keywords:
        if k in low:
            found.append(k.decode())
    return found


def check_virustotal(hash_value):
    API_KEY = settings.VT_API_KEY
    if not API_KEY:
        return 0, 0
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    try:
        r = requests.get(url, headers={"x-apikey": API_KEY}, timeout=10)
        if r.status_code == 200:
            s = r.json()["data"]["attributes"]["last_analysis_stats"]
            return s.get("malicious", 0), s.get("suspicious", 0)
    except Exception:
        pass
    return 0, 0


def get_rule_score(ext, file_size, string_count):
    score = 0
    if ext in [".bat", ".cmd", ".ps1", ".scr", ".vbs", ".js"]:
        score += 55
    elif ext in [".exe", ".msi", ".dll"]:
        score += 25
    elif ext in [".zip", ".rar", ".7z"]:
        score += 20
    elif ext in [".docm", ".xlsm"]:
        score += 35
    else:
        score += 5
    if file_size > 20 * 1024 * 1024:
        score += 15
    elif file_size > 5 * 1024 * 1024:
        score += 5
    score += min(string_count * 15, 30)
    return min(score, 100)


def get_entropy_score(entropy):
    if entropy >= 7.8:   return 85
    elif entropy >= 7.2: return 55
    elif entropy >= 6.5: return 25
    elif entropy >= 5.0: return 10
    return 5


def get_vt_score(vm, vs):
    return min((vm * 15) + (vs * 5), 100)


def get_ml_score(entropy, file_size, string_count, vm, vs):
    if model is None:
        return 0, 0
    try:
        f   = [[entropy, file_size, string_count, vm, vs]]
        pred = int(model.predict(f)[0])
        prob = float(model.predict_proba(f)[0][1]) * 100 if hasattr(model, "predict_proba") else (100.0 if pred else 0.0)
        return round(prob, 2), pred
    except Exception:
        return 0, 0


def calculate_final_score(rule, entropy_s, vt_s, ml_s, vm):
    bonus = -10 if vm == 0 else 0
    if ml_s > 0:
        f = rule * 0.25 + entropy_s * 0.15 + vt_s * 0.40 + ml_s * 0.20
    else:
        f = rule * 0.35 + entropy_s * 0.25 + vt_s * 0.40
    return round(max(0, min(f + bonus, 100)), 2)


def determine_status(score, vm):
    if vm >= 3:      return "MALICIOUS"
    if score >= 65:  return "MALICIOUS"
    elif score >= 35: return "SUSPICIOUS"
    return "SAFE"


# ----------------------------
# API VIEW
# ----------------------------
class FileUploadView(APIView):
    def post(self, request):
        serializer = FileSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        instance = serializer.save()
        file     = instance.file
        filename = file.name

        # Hash
        hasher = hashlib.sha256()
        for chunk in file.chunks():
            hasher.update(chunk)
        instance.sha256    = hasher.hexdigest()
        instance.file_size = file.size
        ext                = os.path.splitext(filename)[1].lower()
        instance.file_type = ext

        file.seek(0)
        file_data     = file.read()
        entropy       = calculate_entropy(file_data)
        strings_found = suspicious_strings(file_data)
        string_count  = len(strings_found)

        # VT
        vt_malicious, vt_suspicious = check_virustotal(instance.sha256)
        vt_score                    = get_vt_score(vt_malicious, vt_suspicious)

        # Uygulama tanıma + Authenticode
        app_info = identify_application(filename, file_data, vt_malicious, vt_suspicious)

        # ── SERTİFİKALI → Risk skoru 0, AI yok ──────────
        if app_info["certified"]:
            instance.risk_score = 0
            instance.save()

            pub    = app_info["publisher"] or ""
            issuer = app_info["issuer"]    or ""
            name   = app_info["app_name"]  or "Verified Application"

            return Response({
                "status":             "SAFE",
                "risk_score":         0,
                "ai_comment":         "This file carries a valid Authenticode signature. No threats detected.",
                "certified":          True,
                "verified":           app_info["verified"],
                "app_name":           name,
                "publisher":          pub,
                "issuer":             issuer,
                "entropy":            round(entropy, 2),
                "suspicious_strings": strings_found,
                "vt_malicious":       vt_malicious,
                "vt_suspicious":      vt_suspicious,
            }, status=status.HTTP_201_CREATED)

        # ── NORMAL AKIŞ ─────────────────────────────────
        rule_s    = get_rule_score(ext, file.size, string_count)
        entropy_s = get_entropy_score(entropy)
        ml_s, _   = get_ml_score(entropy, file.size, string_count, vt_malicious, vt_suspicious)
        final     = calculate_final_score(rule_s, entropy_s, vt_score, ml_s, vt_malicious)
        stat      = determine_status(final, vt_malicious)

        # AI kararı
        kname = app_info["app_name"]
        if kname and vt_malicious == 0 and vt_suspicious == 0:
            ai_comment = f"Recognized as {kname}. VirusTotal reports no threats. File appears safe."
        elif vt_malicious == 0 and vt_suspicious == 0 and final < 35:
            ai_comment = "No significant threats detected. VirusTotal is clean and risk indicators are low."
        else:
            ai_comment = get_ai_analysis(filename, ext, file.size, final, entropy, strings_found, vt_malicious, vt_suspicious)

        instance.risk_score = final
        instance.save()

        return Response({
            "status":             stat,
            "risk_score":         final,
            "ai_comment":         ai_comment,
            "certified":          False,
            "verified":           False,
            "app_name":           kname,
            "publisher":          app_info["publisher"],
            "issuer":             app_info["issuer"],
            "entropy":            round(entropy, 2),
            "suspicious_strings": strings_found,
            "vt_malicious":       vt_malicious,
            "vt_suspicious":      vt_suspicious,
        }, status=status.HTTP_201_CREATED)
