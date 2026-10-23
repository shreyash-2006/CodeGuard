import json
import urllib.request

BASE = "http://127.0.0.1:8000"
CSV = open("examples/sample_codes.csv", encoding="utf-8").read()


def post(path, data, ctype):
    req = urllib.request.Request(BASE + path, data=data, headers={"Content-Type": ctype})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.status, r.headers.get("content-type"), r.read()


# 1. JSON {"csv": ...}
st, ct, body = post("/batch/csv", json.dumps({"csv": CSV}).encode(), "application/json")
d = json.loads(body)
print("JSON      ->", st, "rows", len(d["results"]), "summary", {k: d["summary"][k] for k in ("total", "blocked", "allowed")})
print("           verdict metrics:", d["summary"].get("verdict"))

# 2. raw CSV body
st, ct, body = post("/batch/csv", CSV.encode(), "text/csv")
print("RAW       ->", st, "rows", len(json.loads(body)["results"]))

# 3. ?format=csv download
st, ct, body = post("/batch/csv?format=csv", json.dumps({"csv": CSV}).encode(), "application/json")
print("DL csv    ->", st, ct, "bytes", len(body))
print("           first line:", body.decode().splitlines()[0])
print("           second line:", body.decode().splitlines()[1][:90], "...")
