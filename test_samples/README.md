## Safe test samples (DO NOT EXECUTE)

These files are **safe demo samples** meant to test the UI states (**SAFE / SUSPICIOUS / MALICIOUS**) without downloading real malware.

- **`suspicious_demo.ps1`**: Contains suspicious keywords as plain text to trigger heuristic indicators.
- **`suspicious_demo.bat`**: Same idea for batch scripts.
- **`eicar_encoded.txt`**: Encoded EICAR test string (not real malware). We keep it encoded because some AV tools quarantine the raw string in a repo.

### Optional: generate a high-entropy sample

From the project root:

```powershell
.\venv\Scripts\python.exe .\tools\generate_eicar_sample.py
.\venv\Scripts\python.exe .\tools\generate_entropy_sample.py
```

`generate_eicar_sample.py` will create `test_samples/eicar.com.txt` locally for VT/AV-style testing.

It will create `test_samples/high_entropy.bin` (random bytes). Upload it to see how entropy affects scoring.

