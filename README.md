# URL Phishing Scanner

A small defensive security tool. Paste a URL; it extracts a set of
features, scores each one, and returns a verdict with a full breakdown
of why. Rules-based on purpose, so every point is explainable.

## How it works
1. `detector.py` parses the URL string (no network calls) and runs ~12
   heuristic checks: raw-IP host, `@` redirect trick, punycode, suspicious
   TLDs, URL shorteners, subdomain padding, keyword stuffing, length,
   host entropy, and more.
2. Each triggered check adds weighted points.
3. Total score maps to: Probably Safe (<25) / Suspicious (25-49) /
   Likely Phishing (50+).

## Run
```
pip install -r requirements.txt
python app.py
```
Open http://localhost:5000

## Test the logic directly
```
python detector.py
```

## Limitations (be honest about these in interviews)
- Heuristic, not ML; tuned weights, not learned.
- `_registered_domain` uses the last two labels, so it is not
  public-suffix accurate (misreads things like `co.uk`).
- No live reputation/blocklist lookups.

These are deliberate scoping choices for a learning project, and each is
a clear "next step" you can talk about.
