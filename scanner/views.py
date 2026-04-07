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

from .serializers import FileSerializer


# ----------------------------
# FRONTEND VIEW
# ----------------------------
def home(request):
    return render(request, "upload.html")


# ----------------------------
# OPTIONAL ML MODEL LOAD
# ----------------------------
try:
    model = joblib.load("model.pkl")
except Exception:
    model = None


# ----------------------------
# HELPERS
# ----------------------------
def calculate_entropy(data):
    if not data:
        return 0.0

    counter = Counter(data)
    length = len(data)

    entropy = 0.0
    for count in counter.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def suspicious_strings(data):
    keywords = [
        b"cmd", b"powershell", b"wget", b"curl",
        b"exec", b"base64", b"http", b"https",
        b"shell", b"chmod"
    ]

    found = []
    lower_data = data.lower()

    for key in keywords:
        if key in lower_data:
            found.append(key.decode())

    return found


# 🔥 FIXED VT FUNCTION
def check_virustotal(hash_value):
    API_KEY = settings.VT_API_KEY

    if not API_KEY:
        return 0, 0

    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]

            return stats.get("malicious", 0), stats.get("suspicious", 0)

    except:
        pass

    return 0, 0


def get_rule_score(file_ext, file_size, string_count):
    score = 0

    if file_ext in [".exe", ".bat", ".cmd", ".msi", ".ps1", ".dll", ".scr"]:
        score += 60
    elif file_ext in [".zip", ".rar", ".7z"]:
        score += 25
    elif file_ext in [".docm", ".xlsm"]:
        score += 40
    else:
        score += 10

    if file_size > 20 * 1024 * 1024:
        score += 20
    elif file_size > 5 * 1024 * 1024:
        score += 10

    score += min(string_count * 10, 30)

    return min(score, 100)


def get_entropy_score(entropy):
    if entropy >= 7.5:
        return 90
    elif entropy >= 7.0:
        return 70
    elif entropy >= 6.5:
        return 50
    elif entropy >= 5.5:
        return 25
    return 5


def get_vt_score(vt_malicious, vt_suspicious):
    return min((vt_malicious * 12) + (vt_suspicious * 6), 100)


def get_ml_score(entropy, file_size, string_count, vt_malicious, vt_suspicious):
    if model is None:
        return 0, 0

    try:
        features = [[entropy, file_size, string_count, vt_malicious, vt_suspicious]]
        prediction = int(model.predict(features)[0])

        if hasattr(model, "predict_proba"):
            probability = float(model.predict_proba(features)[0][1]) * 100
        else:
            probability = 100.0 if prediction == 1 else 0.0

        return round(probability, 2), prediction

    except:
        return 0, 0


def calculate_final_score(rule_score, entropy_score, vt_score, ml_score):
    final = (
        rule_score * 0.30 +
        entropy_score * 0.20 +
        vt_score * 0.30 +
        ml_score * 0.20
    )
    return round(min(final, 100), 2)


def determine_status(final_score, vt_malicious):
    if vt_malicious >= 5:
        return "MALICIOUS"
    if final_score >= 70:
        return "MALICIOUS"
    elif final_score >= 40:
        return "SUSPICIOUS"
    return "SAFE"


def generate_ai_comment(status_value, final_score, entropy, strings_found, vt_malicious, vt_suspicious, ml_score, ml_prediction):
    comments = []

    if status_value == "MALICIOUS":
        comments.append("This file is highly suspicious and may be dangerous.")
    elif status_value == "SUSPICIOUS":
        comments.append("This file shows suspicious indicators and should be handled carefully.")
    else:
        comments.append("This file appears safe with no major threat indicators.")

    if vt_malicious > 0:
        comments.append(f"VirusTotal detected {vt_malicious} malicious and {vt_suspicious} suspicious flags.")

    if entropy >= 7.5:
        comments.append("High entropy suggests possible obfuscation or packing.")

    if strings_found:
        comments.append(f"Detected suspicious strings: {', '.join(strings_found)}.")

    if ml_prediction == 1:
        comments.append(f"ML model predicts malicious behavior ({ml_score}% confidence).")

    comments.append(f"Final risk score is {final_score}%.")

    return " ".join(comments)


# ----------------------------
# API VIEW
# ----------------------------
class FileUploadView(APIView):
    def post(self, request):
        serializer = FileSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        instance = serializer.save()
        file = instance.file

        # HASH
        hasher = hashlib.sha256()
        for chunk in file.chunks():
            hasher.update(chunk)
        instance.sha256 = hasher.hexdigest()

        # FILE INFO
        instance.file_size = file.size
        ext = os.path.splitext(file.name)[1].lower()
        instance.file_type = ext

        # FILE CONTENT
        file.seek(0)
        file_data = file.read()

        entropy = calculate_entropy(file_data)
        strings_found = suspicious_strings(file_data)
        string_count = len(strings_found)

        file.seek(0)

        # SCORES
        rule_score = get_rule_score(ext, file.size, string_count)
        entropy_score = get_entropy_score(entropy)

        vt_malicious, vt_suspicious = check_virustotal(instance.sha256)
        vt_score = get_vt_score(vt_malicious, vt_suspicious)

        ml_score, ml_prediction = get_ml_score(
            entropy, file.size, string_count, vt_malicious, vt_suspicious
        )

        final_score = calculate_final_score(
            rule_score, entropy_score, vt_score, ml_score
        )

        status_value = determine_status(final_score, vt_malicious)

        ai_comment = generate_ai_comment(
            status_value, final_score, entropy, strings_found,
            vt_malicious, vt_suspicious, ml_score, ml_prediction
        )

        # SAVE
        instance.risk_score = final_score
        instance.save()

        return Response({
            "status": status_value,
            "risk_score": final_score,
            "ai_comment": ai_comment,

            "entropy": round(entropy, 2),
            "suspicious_strings": strings_found,

            "vt_malicious": vt_malicious,
            "vt_suspicious": vt_suspicious,
        }, status=status.HTTP_201_CREATED)