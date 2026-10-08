# Analisi dei risultati di validate.py: rigenera tutti i numeri della tesi leggendo solo i JSON su disco
# (nessuna simulazione, niente XSB né torch: basta un python3 qualsiasi, solo libreria standard).
#
# Uso (dalla root del repo):
#     python oracle/analyze.py                         # analizza oracle_results/, confronta con results/
#     python oracle/analyze.py -r results/ /percorso/run_senza_oracolo   # più cartelle di confronto
#
# Sezioni:
#     1. validità dell'esecuzione: discrepanze XSB vs reference.fixpoint, query e cache (da validate.log)
#     2. violazioni: scadute/altre, gap t-1 - last_derivable_day, per tipo e per zona
#     3. raggiungibilità del goal secondo MulVAL: primo giorno, cali di raggiungibilità senza difensore
#     4. esposizione MulVAL vs vittorie del simulatore: per fasce, Spearman tra scenari
#     5. confronto appaiato tra politiche del difensore (stesso seme per episodio in tutti gli scenari):
#        test dei segni sull'esposizione, McNemar esatto sulle vittorie, correzione di Bonferroni
#     6. effetto dell'effort del difensore
#     7. non-interferenza: JSON di vulnGym confrontati byte per byte con le cartelle di riferimento

import argparse
import glob
import json
import math
import os
import re
import statistics as st
from collections import Counter, defaultdict
from itertools import combinations

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

STALE_DAYS = 3  # deve coincidere con validate.stale
ALPHA = 0.05
POLICIES = {1: "NoDef", 2: "Importance", 3: "Severity", 4: "Centrality"}
EXPOSURE_BINS = [(0, 0), (1, 30), (31, 90), (91, 180), (181, 270), (271, 365)]


# ---------------------------------------------------------------- caricamento


def load(out: str) -> list[dict]:
    """Uno per (esperimento, scenario): il JSON dell'oracolo più i campi ricavati dal nome della cartella."""
    runs = []
    for path in sorted(glob.glob(os.path.join(out, "exp_*", "oracle", "*.json"))):
        exp_dir = path.split(os.sep)[-3]  # exp_01__APT28__DoS__Layered__effort_0.5
        m = re.match(r"exp_(\d+)__(\w+?)__\w+?__(\w+?)__effort_([\d.]+)$", exp_dir)
        sc = int(re.search(r"Scenario_(\d)", os.path.basename(path)).group(1))
        with open(path, encoding="utf-8") as f:
            r = json.load(f)
        r |= {
            "exp_dir": exp_dir,
            "exp": int(m.group(1)),
            "apt_name": m.group(2),
            "topology": m.group(3),
            "effort": float(m.group(4)),
            "sc": sc,
            "group": f"{m.group(2)} {m.group(3)}",
        }
        runs.append(r)
    return runs


def wins(r: dict) -> list[bool]:
    return [ep["sim_time_to_goal"] is not None for ep in r["episodes"]]


def exposure(r: dict) -> list[int]:
    return [ep["exposure_days"] for ep in r["episodes"]]


def reachable(r: dict, ep: dict) -> list[bool]:
    return [n >= r["target_goals"] for n in ep["db_reachable"]]


# ---------------------------------------------------------------- statistica (senza scipy)


def ranks(v: list[float]) -> list[float]:
    """Ranghi con i pari merito alla media (come scipy.stats.rankdata)."""
    order = sorted(range(len(v)), key=lambda i: v[i])
    r = [0.0] * len(v)
    i = 0
    while i < len(v):
        j = i
        while j + 1 < len(v) and v[order[j + 1]] == v[order[i]]:
            j += 1
        for k in range(i, j + 1):
            r[order[k]] = (i + j) / 2
        i = j + 1
    return r


def pearson(x: list[float], y: list[float]) -> float:
    mx, my = st.mean(x), st.mean(y)
    num = sum((a - mx) * (b - my) for a, b in zip(x, y))
    return num / math.sqrt(
        sum((a - mx) ** 2 for a in x) * sum((b - my) ** 2 for b in y)
    )


def spearman(x: list[float], y: list[float]) -> float:
    return pearson(ranks(x), ranks(y))


def binom_two_sided(b: int, c: int) -> float:
    """Test binomiale esatto a due code con p = 1/2 su b successi contro c: è sia il test dei segni
    (b = coppie in cui A < B, c = coppie in cui A > B, pari esclusi) sia il McNemar esatto
    (b, c = coppie discordanti)."""
    n = b + c
    if n == 0:
        return 1.0
    return min(1.0, 2 * sum(math.comb(n, i) for i in range(min(b, c) + 1)) / 2**n)


def fmt_p(p: float, m: int) -> str:
    """p grezzo, p corretto con Bonferroni su m test, asterisco se significativo dopo la correzione."""
    adj = min(1.0, p * m)
    return f"p={p:.2g} (Bonf {adj:.2g}){' *' if adj < ALPHA else '  '}"


# ---------------------------------------------------------------- sezioni


def section(title: str):
    print(f"\n{'=' * 100}\n{title}\n{'=' * 100}")


def validity(runs: list[dict], out: str):
    section("1. VALIDITÀ DELL'ESECUZIONE")
    mism = sum(len(r["xsb_mismatches"]) for r in runs)
    eps = sum(len(r["episodes"]) for r in runs)
    print(f"scenari {len(runs)}, episodi {eps}")
    print(
        f"stati in cui XSB differisce da reference.fixpoint: {mism}"
        + ("  <-- RISULTATI NON VALIDI" if mism else "")
    )
    log = os.path.join(out, "validate.log")
    if os.path.exists(log):
        with open(log, encoding="utf-8", errors="replace") as f:
            q = re.findall(
                r"Query MulVAL in questa run: (\d+), stati riusati dalla cache: (\d+)",
                f.read(),
            )
        if q:  # ultima riga: una run ripresa con -e ne stampa una per ripresa
            print(
                f"query XSB {q[-1][0]}, stati riusati dalla cache {q[-1][1]} (da validate.log, ultima run)"
            )


def violations(runs: list[dict]):
    section(
        "2. VIOLAZIONI (conquista nel simulatore al giorno t non derivabile da MulVAL a t-1)"
    )
    viol = [(r, v) for r in runs for ep in r["episodes"] for v in ep["violations"]]
    gaps = Counter()
    never = 0
    for _, v in viol:
        if v["last_derivable_day"] is None:
            never += 1
        else:
            gaps[v["day"] - 1 - v["last_derivable_day"]] += 1
    stale = sum(n for g, n in gaps.items() if g <= STALE_DAYS)
    print(
        f"totale {len(viol)}: scadute (gap <= {STALE_DAYS}) {stale}, altre {len(viol) - stale} "
        f"(di cui mai derivabili nell'episodio {never})"
    )
    print(
        "gap t-1 - last_derivable_day:",
        ", ".join(f"{g}→{n}" for g, n in sorted(gaps.items())),
    )
    print(
        "per tipo:",
        ", ".join(
            f"{k} {n}" for k, n in Counter(v["kind"] for _, v in viol).most_common()
        ),
    )
    print(
        "per zona:",
        ", ".join(
            f"{k} {n}" for k, n in Counter(v["zone"] for _, v in viol).most_common()
        ),
    )
    by_sc = Counter(POLICIES[r["sc"]] for r, _ in viol)
    print("per scenario:", ", ".join(f"{p} {by_sc[p]}" for p in POLICIES.values()))
    by_group = Counter(r["group"] for r, _ in viol)
    print(
        "per APT/topologia:", ", ".join(f"{g} {n}" for g, n in sorted(by_group.items()))
    )


def no_defender_identical(runs: list[dict]) -> dict:
    """Lo scenario 1 non ha difensore, quindi l'effort non conta: deve essere identico tra i 3 effort.
    Restituisce gli scenari distinti (lo scenario 1 una sola volta per APT/topologia)."""
    sc1 = defaultdict(list)
    for r in runs:
        if r["sc"] == 1:
            sc1[r["group"]].append(r)
    for g, rs in sorted(sc1.items()):
        same = all(x["episodes"] == rs[0]["episodes"] for x in rs[1:])
        print(
            f"scenario 1 identico tra gli effort in {g}: {'sì' if same else 'NO'} ({len(rs)} esperimenti)"
        )
    keep = {id(rs[0]) for rs in sc1.values()}
    return [r for r in runs if r["sc"] != 1 or id(r) in keep]


def reachability(runs: list[dict]):
    section("3. RAGGIUNGIBILITÀ DEL GOAL SECONDO MULVAL")
    ever = sum(
        ep["mulval_first_reachable"] is not None for r in runs for ep in r["episodes"]
    )
    tot = sum(len(r["episodes"]) for r in runs)
    print(f"episodi con goal raggiungibile almeno un giorno: {ever}/{tot}")
    print(
        "primo giorno raggiungibile (mediana, min-max) per APT e politica del difensore:"
    )
    for apt in sorted({r["apt_name"] for r in runs}):
        cols = []
        for sc, name in POLICIES.items():
            first = [
                ep["mulval_first_reachable"]
                for r in runs
                if r["apt_name"] == apt and r["sc"] == sc
                for ep in r["episodes"]
                if ep["mulval_first_reachable"] is not None
            ]
            cols.append(f"{name} {st.median(first):g} ({min(first)}-{max(first)})")
        print(f"  {apt}: " + ", ".join(cols))

    print(
        "\nCali di raggiungibilità (vera un giorno, falsa il successivo) SENZA difensore (scenario 1):"
    )
    print(
        "solo l'attaccante può averli causati, es. DoS di un nodo di ingresso (nodeOff) che gli chiude la strada"
    )
    seen = set()
    for r in runs:
        if r["sc"] != 1:
            continue
        for ep in r["episodes"]:
            R = reachable(r, ep)
            drops = [d + 1 for d in range(len(R) - 1) if R[d] and not R[d + 1]]
            if not drops:
                continue
            back = next((d for d in range(drops[0], len(R)) if R[d]), None)
            key = (r["group"], ep["episode"])
            note = " (stesso episodio degli altri effort)" if key in seen else ""
            seen.add(key)
            print(
                f"  esp.{r['exp']:2} {r['group']:<16} ep.{ep['episode']:3}: non raggiungibile dal giorno "
                f"{drops[0]}, di nuovo dal giorno {back}{note}"
            )
    if not seen:
        print("  nessuno")


def exposure_vs_wins(runs: list[dict]):
    section(
        "4. ESPOSIZIONE (giorni con goal raggiungibile per MulVAL) vs VITTORIE DEL SIMULATORE"
    )
    distinct = no_defender_identical(runs)
    pairs = [(e, w) for r in runs for e, w in zip(exposure(r), wins(r))]
    print(f"tutti i {len(pairs)} episodi, per fascia di esposizione:")
    for a, b in EXPOSURE_BINS:
        sel = [w for e, w in pairs if a <= e <= b]
        if sel:
            print(
                f"  {a:>3}-{b:<3} giorni: episodi {len(sel):5}, vittorie sim {sum(sel) / len(sel):6.1%}"
            )

    def corr(rs: list[dict]) -> str:
        E = [st.mean(exposure(r)) for r in rs]
        W = [sum(wins(r)) for r in rs]
        return f"Spearman {spearman(E, W):.2f} (Pearson {pearson(E, W):.2f}, {len(rs)} scenari)"

    print(
        f"\nlivello scenario (esposizione media vs vittorie), scenario 1 contato una volta per gruppo:"
    )
    print(f"  tutti: {corr(distinct)}")
    for g in sorted({r["group"] for r in distinct}):
        print(f"  {g:<16} {corr([r for r in distinct if r['group'] == g])}")


def paired(runs: list[dict]):
    section("5. CONFRONTO APPAIATO TRA POLITICHE DEL DIFENSORE")
    by = {(r["exp"], r["sc"]): r for r in runs}
    exps = sorted({r["exp"] for r in runs})
    m = len(exps)
    print("episodio i = stesso seme in tutti gli scenari → coppie di episodi.")
    print(
        "esposizione: test dei segni (A<B contro A>B, pari esclusi); vittorie: McNemar esatto (solo A, solo B)."
    )
    print(
        f"Bonferroni su {m} esperimenti per ciascun confronto e metrica; * = significativo a {ALPHA} dopo la correzione"
    )
    for a, b in combinations((2, 3, 4), 2):
        A, B = POLICIES[a], POLICIES[b]
        print(f"\n{A} (A) vs {B} (B)")
        sig_e = sig_w = 0
        for e in exps:
            ra, rb = by[(e, a)], by[(e, b)]
            ea, eb = exposure(ra), exposure(rb)
            lo, hi = (
                sum(x < y for x, y in zip(ea, eb)),
                sum(x > y for x, y in zip(ea, eb)),
            )
            wa, wb = wins(ra), wins(rb)
            only_a, only_b = (
                sum(x and not y for x, y in zip(wa, wb)),
                sum(y and not x for x, y in zip(wa, wb)),
            )
            pe, pw = binom_two_sided(lo, hi), binom_two_sided(only_a, only_b)
            sig_e += pe * m < ALPHA
            sig_w += pw * m < ALPHA
            print(
                f"  esp.{e:2} {ra['group']:<16} eff {ra['effort']}: "
                f"esposizione media {st.mean(ea):5.1f}/{st.mean(eb):5.1f}, A<B {lo:3} A>B {hi:3} {fmt_p(pe, m)} | "
                f"vittorie {sum(wa):3}/{sum(wb):3}, solo A {only_a:2} solo B {only_b:2} {fmt_p(pw, m)}"
            )
        print(
            f"  significativi dopo Bonferroni: esposizione {sig_e}/{m}, vittorie {sig_w}/{m}"
        )


def effort(runs: list[dict]):
    section("6. EFFETTO DELL'EFFORT DEL DIFENSORE (stesso APT, topologia e politica)")
    cells = defaultdict(dict)
    for r in runs:
        if r["sc"] != 1:
            cells[(r["group"], r["sc"])][r["effort"]] = r
    for (g, sc), by_eff in sorted(cells.items()):
        effs = sorted(by_eff)
        E = [st.mean(exposure(by_eff[x])) for x in effs]
        W = [sum(wins(by_eff[x])) for x in effs]

        def trend(v):
            return (
                "crescente"
                if all(x <= y for x, y in zip(v, v[1:]))
                else "decrescente"
                if all(x >= y for x, y in zip(v, v[1:]))
                else "non monotona"
            )

        print(
            f"{g:<16} {POLICIES[sc]:<10} effort {effs}: esposizione {[round(x, 1) for x in E]} ({trend(E)}), "
            f"vittorie {W} ({trend(W)})"
        )


def non_interference(out: str, refs: list[str]):
    section("7. NON-INTERFERENZA (JSON di vulnGym identici byte per byte)")
    mine = sorted(glob.glob(os.path.join(out, "exp_*", "scenarios", "*.json")))
    for ref in refs:
        diff, missing = [], 0
        for p in mine:
            q = os.path.join(ref, *p.split(os.sep)[-3:])
            if not os.path.exists(q):
                missing += 1
                continue
            with open(p, "rb") as f1, open(q, "rb") as f2:
                if f1.read() != f2.read():
                    diff.append(os.sep.join(p.split(os.sep)[-3:]))
        print(
            f"vs {ref}: identici {len(mine) - len(diff) - missing}/{len(mine)}, diversi {len(diff)}, "
            f"assenti {missing}"
        )
        for d in diff:
            print(f"  diverso: {d}")


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "-o",
        "--out",
        default=os.path.join(REPO, "oracle_results"),
        help="cartella prodotta da validate.py",
    )
    ap.add_argument(
        "-r",
        "--ref",
        nargs="*",
        default=[os.path.join(REPO, "results")],
        help="cartelle con cui confrontare i JSON di vulnGym (es. results/ o una run --no-oracle)",
    )
    args = ap.parse_args()

    runs = load(args.out)
    if not runs:
        raise SystemExit(f"nessun risultato in {args.out}")
    validity(runs, args.out)
    violations(runs)
    reachability(runs)
    exposure_vs_wins(runs)
    paired(runs)
    effort(runs)
    non_interference(args.out, args.ref)


if __name__ == "__main__":
    main()
