# Validazione di vulnGym con MulVAL: esegue i test del relatore (testing.test, come code/main.py)
# con l'oracolo agganciato tramite monkeypatch, senza modificare il codice in code/.
#
# Uso (dentro la FHS, venv attivo, dalla root del repo):
#     python oracle/validate.py                          # tutti gli esperimenti, 100 episodi
#     python oracle/validate.py -e 1 7 -n 3              # esperimenti 1 e 7, 3 episodi per scenario
#     python oracle/validate.py -e 1 -n 3 --no-oracle    # stessa run senza oracolo (controllo di non-interferenza)
#     python oracle/validate.py -e 5 6 7 8 9 10 11 12    # ripresa dopo un'interruzione (gli scenari finiti restano su disco)
#     python oracle/validate.py --summary-only           # rigenera solo summary.csv da ciò che è su disco
#
# Output in --out (default: oracle_results/):
#     <exp_dir>/scenarios/*.json   JSON di vulnGym (identici a results/ se l'oracolo non interferisce)
#     <exp_dir>/oracle/*.json      per episodio: db_reachable per giorno, violazioni, latenza, esposizione;
#                                  xsb_mismatches: stati in cui XSB differisce da reference.py (devono essere 0)
#     summary.csv                  una riga per (esperimento, scenario), ricostruito da TUTTI gli <exp_dir>/oracle/*.json
#                                  presenti in --out: ogni scenario è salvato appena finisce, quindi una run interrotta
#                                  si riprende lanciando solo gli esperimenti mancanti

import argparse
import csv
import glob
import json
import os
import sys
import time

# CPU: è con la CPU che i risultati coincidono con quelli versionati in results/
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "code"))

import simulation_parameters as sp
import logger
import Vulnerability
import testing
from NetworkExplorationEnv import NetworkExplorationEnv
from Scenario import Scenario


def install_oracle(oracle):
    """Avvolge i metodi delle classi di vulnGym: prima l'originale, poi l'oracolo osserva."""
    orig_reset = NetworkExplorationEnv.reset
    orig_step = NetworkExplorationEnv.step
    orig_run = Scenario.run_scenario

    def reset(self, seed):
        out = orig_reset(self, seed)
        oracle.reset(self)
        return out

    def step(self, attacker_action, defender_action):
        out = orig_step(self, attacker_action, defender_action)
        oracle.observe(self)
        return out

    def run_scenario(self, num_episodes, seed):
        oracle.begin_scenario(self.name)
        out = orig_run(self, num_episodes, seed)
        res = oracle.end_scenario()
        path = os.path.join(sp.exp_dir, "oracle", f"{self.name.replace(' ', '_')}.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(res, f)
        return out

    NetworkExplorationEnv.reset = reset
    NetworkExplorationEnv.step = step
    Scenario.run_scenario = run_scenario


def stale(v: dict) -> bool:
    last = v.get("last_derivable_day")
    return last is not None and v["day"] - 1 - last <= 3


def summarize(res: dict) -> dict:
    eps = res["episodes"]
    viol = [v for ep in eps for v in ep["violations"]]
    lat = [ep["latency"] for ep in eps if ep["latency"] is not None]
    return {
        "experiment": res["experiment"],
        "scenario": res["scenario"],
        "episodes": len(eps),
        "xsb_mismatches": len(res["xsb_mismatches"]),
        "sim_goals": sum(ep["sim_time_to_goal"] is not None for ep in eps),
        "mulval_ever_reachable": sum(
            ep["mulval_first_reachable"] is not None for ep in eps
        ),
        "mean_exposure_days": round(
            sum(ep["exposure_days"] for ep in eps) / len(eps), 1
        ),
        "mean_latency_days": round(sum(lat) / len(lat), 1) if lat else "",
        "violations": len(viol),
        # precondizione vera alla scelta del bersaglio ma scaduta prima dell'esecuzione (vedi mulval_oracle)
        "viol_stale": sum(stale(v) for v in viol),
        "viol_other": sum(not stale(v) for v in viol),
        **{
            f"viol_{k}": sum(v["kind"] == k for v in viol)
            for k in ("access", "credentials", "data", "dos", "goal")
        },
    }


def write_summary(out: str) -> list[dict]:
    """Riassume tutti gli scenari salvati in out (anche quelli di run precedenti) in summary.csv."""
    rows = []
    for path in sorted(glob.glob(os.path.join(out, "*", "oracle", "*.json"))):
        with open(path, encoding="utf-8") as f:
            # sp.EXPERIMENT (es. APT28_layered_2020) è uguale per i 3 effort: si usa la cartella dell'esperimento
            rows.append(
                summarize(json.load(f)) | {"experiment": path.split(os.sep)[-3]}
            )
    if rows:
        with open(os.path.join(out, "summary.csv"), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
    return rows


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "-e",
        "--experiments",
        type=int,
        nargs="+",
        default=list(range(1, sp.NUM_EXPERIMENTS + 1)),
    )
    ap.add_argument("-n", "--episodes", type=int, default=sp.TEST_EPISODES)
    ap.add_argument("-o", "--out", default=os.path.join(REPO, "oracle_results"))
    ap.add_argument(
        "--no-oracle", action="store_true", help="esegui senza oracolo (baseline)"
    )
    ap.add_argument(
        "--summary-only",
        action="store_true",
        help="non eseguire nulla: rigenera summary.csv dai risultati già su disco",
    )
    args = ap.parse_args()

    oracle = None
    if not (args.no_oracle or args.summary_only):
        from mulval_oracle import MulvalOracle

        oracle = MulvalOracle()
        install_oracle(oracle)

    logger.DISABLE_FILE_LOG = True
    dataset, dataset_key = None, None

    for exp_id in [] if args.summary_only else args.experiments:
        sp.load_experiment(exp_id)
        sp.TEST_EPISODES = args.episodes
        sp.exp_dir = os.path.join(
            args.out, os.path.basename(sp.exp_dir)
        )  # mai in results/
        logger.setup_experiment_loggers(exp_id)

        if not os.path.exists(f"{sp.MODEL_PATH}/dqn_attacker_trained.pth"):
            print(
                f"Esperimento {exp_id}: nessun modello addestrato in {sp.MODEL_PATH}, salto."
            )
            continue
        if dataset_key != sp.EXPERIMENT:
            dataset = Vulnerability.load_vulnerabilities_from_dataset(sp.DATASET_PATH)
            dataset_key = sp.EXPERIMENT

        print(
            f"\n===== Esperimento {exp_id}: {sp.APT_NAME}, {sp.goal}, {sp.TOPOLOGY}, "
            f"effort {sp.DEFENDER_EFFORT} ====="
        )
        t0 = time.time()
        testing.test(dataset, sp.TOPOLOGY)
        print(f"Esperimento {exp_id} completato in {time.time() - t0:.1f}s", flush=True)

    if args.no_oracle:
        return

    rows = write_summary(args.out)
    if oracle is not None:
        print(
            f"\nQuery MulVAL in questa run: {oracle.queries}, stati riusati dalla cache: {oracle.cache_hits}"
        )
    mismatches = sum(r["xsb_mismatches"] for r in rows)
    print(
        f"Stati in cui XSB differisce dal punto fisso di riferimento (tutti gli scenari su disco): "
        f"{mismatches}" + ("  <-- RISULTATI NON VALIDI" if mismatches else "")
    )
    for r in rows:
        print(
            f"{r['experiment']:<44} {r['scenario']:<56} goal sim {r['sim_goals']}/{r['episodes']}  "
            f"raggiungibile MulVAL {r['mulval_ever_reachable']}/{r['episodes']}  "
            f"esposizione {r['mean_exposure_days']}gg  latenza {r['mean_latency_days'] or '-'}gg  "
            f"violazioni {r['violations']} (scadute {r['viol_stale']}, altre {r['viol_other']})"
        )
    print(f"\nRisultati in {args.out} ({len(rows)} scenari)")


if __name__ == "__main__":
    main()
