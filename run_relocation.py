"""
Attacker-picks-the-channel test.

For every logged SUCCESSFUL attack in AgentDyn's saved runs, the attacker's text is removed from where
the benchmark put it and re-planted in a different channel (an email, a calendar event, a file, a web
page...) that the agent read BEFORE the harmful call. The agent's actions stay exactly as logged, i.e.
we assume the agent was fully hijacked. The only question is: does the gate still block the harmful call?

Usage (needs ./AgentDyn next to this file: git clone https://github.com/leolee99/AgentDyn.git):
    python run_relocation.py                    # held-out split, gates v1 and v4
    python run_relocation.py --split dev
    python run_relocation.py --gates v4
Offline: reads log files only, calls no model.
"""
import argparse
import importlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)
sys.path.insert(0, HERE)

GATES = {"v0": "v0_gate", "v1": "v1_gate", "v4": "v4_gate"}
SPLITS = {"dev": "undefended", "heldout": "other_defenses"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", choices=sorted(SPLITS), default="heldout",
                    help="dev = runs of undefended models (rules were developed on these); "
                         "heldout = runs made with 8 other defenses (never used for tuning)")
    ap.add_argument("--gates", nargs="+", choices=sorted(GATES), default=["v1", "v4"])
    args = ap.parse_args()
    if not os.path.isdir("AgentDyn/runs"):
        sys.exit("AgentDyn/runs not found. Run: git clone https://github.com/leolee99/AgentDyn.git")

    import reloc as R
    gates = {n: importlib.import_module(GATES[n]).Gate for n in args.gates}
    res = R.run(gates, SPLITS[args.split])
    R.show(res)
    os.makedirs("results", exist_ok=True)
    out = {n: {ch: dict(c) for ch, c in chans.items()} for n, chans in res.items()}
    path = f"results/relocation_{args.split}.json"
    json.dump(out, open(path, "w"), indent=1, sort_keys=True)
    print("saved", path)


if __name__ == "__main__":
    main()
