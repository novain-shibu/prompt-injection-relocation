"""
Context numbers: how the gates do on attacks exactly where the benchmark logged them (no relocation).

    python run_logged.py            # gates v1 and v4, dev and held-out splits
Offline: reads log files only, calls no model.
"""
import importlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)
sys.path.insert(0, HERE)


def main():
    if not os.path.isdir("AgentDyn/runs"):
        sys.exit("AgentDyn/runs not found. Run: git clone https://github.com/leolee99/AgentDyn.git")
    import evaluate as E
    import heldout as H
    out = {}
    for name in ("v1", "v4"):
        G = importlib.import_module(f"{name}_gate").Gate
        st = E.evaluate(G, "undefended")[0]
        tot, per = H.run(G)
        out[name] = {
            "dev": {"attacks_succeeded_in_log": st["succeeded"], "stopped": st["stopped"],
                    "clean_runs_ok": st["clean_ok"], "clean_runs_blocked": st["clean_ok_blocked"],
                    "attacked_runs_task_ok": st["util_ok"], "attacked_runs_legit_blocked": st["util_ok_legit_blocked"]},
            "heldout": {"attacks_succeeded_in_log": tot["succ"], "stopped": tot["stop"],
                        "harmful_call_not_located": tot["harm_not_found"],
                        "clean_runs_ok": tot["clean_ok"], "clean_runs_blocked": tot["clean_blk"],
                        "attacked_runs_task_ok": tot["util"], "attacked_runs_legit_blocked": tot["util_blk"],
                        "per_defense": {k: dict(v) for k, v in per.items() if v}},
        }
        p = lambda a, b: f"{a}/{b} = {100 * a / max(1, b):.1f}%"
        for split, s in out[name].items():
            print(f"{name} {split:8s} stopped {p(s['stopped'], s['attacks_succeeded_in_log']):20s} "
                  f"clean blocked {p(s['clean_runs_blocked'], s['clean_runs_ok']):18s} "
                  f"legit blocked under attack {p(s['attacked_runs_legit_blocked'], s['attacked_runs_task_ok'])}")
    os.makedirs("results", exist_ok=True)
    json.dump(out, open("results/logged.json", "w"), indent=1, sort_keys=True)
    print("saved results/logged.json")


if __name__ == "__main__":
    main()
