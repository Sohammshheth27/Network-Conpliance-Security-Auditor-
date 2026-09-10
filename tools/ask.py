"""Send a prompt file to a local model and write clean output -- no spinner."""
import json, sys, time, urllib.request

model = sys.argv[1] if len(sys.argv) > 1 else "qwen3.5:9b"
src   = sys.argv[2] if len(sys.argv) > 2 else r"E:\NCSA\prompts\sonicwall_real_full.txt"
out   = sys.argv[3] if len(sys.argv) > 3 else r"E:\NCSA\prompts\answer.txt"
think = (sys.argv[4].lower() == "true") if len(sys.argv) > 4 else True

prompt = open(src, encoding="utf-8").read()
payload = {"model": model, "prompt": prompt, "think": think, "stream": False,
           "options": {"temperature": 0, "num_ctx": 32768}}
req = urllib.request.Request("http://127.0.0.1:11434/api/generate",
                             data=json.dumps(payload).encode(),
                             headers={"Content-Type": "application/json"})
t0 = time.time()
with urllib.request.urlopen(req, timeout=7200) as r:
    d = json.loads(r.read().decode())
el = time.time() - t0

body = d.get("response", "")
with open(out, "w", encoding="utf-8") as fh:
    fh.write(body)

tok = d.get("eval_count", 0)
print(f"model      : {model}   thinking={think}")
print(f"prompt     : {len(prompt)} chars")
print(f"elapsed    : {el:.0f}s")
print(f"out tokens : {tok}   ({tok/max(d.get('eval_duration',1)/1e9,0.01):.1f} tok/s)")
print(f"written    : {out}  ({len(body)} chars)")
