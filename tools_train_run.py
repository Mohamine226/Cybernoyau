import sys, time; sys.path.insert(0, '.')
from cubernoyau.training import ember_model as E
t = time.time(); last = [0]
def prog(i, n, msg):
    if i - last[0] >= 25 or i == 0 or "Eval" in msg or "Term" in msg:
        last[0] = i; print(f"[{time.time()-t:6.0f}s] {i}/{n} {msg}", flush=True)
meta = E.train_from_sources(None, profile="rapide", progress=prog)
import json; print(json.dumps({k: meta[k] for k in ("name","num_iterations","n_train","n_valid","n_test","thresholds","metrics")}, indent=1))
