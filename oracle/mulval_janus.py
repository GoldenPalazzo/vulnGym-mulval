# Ponte Python <---> MulVAL (XSB) tramite Janus.
#
# Richiede XSB compilato con scheduling BATCHED (bin/xsb-btc) e janus_xsb installato contro quella
# configurazione: con lo scheduling local di default XSB restituisce risposte incomplete.
# Su XSB batched jns.query_once va in segfault, quindi tutto passa da predicati di appoggio definiti
# in janus_helpers.P.
#
# Memoria: in janus_xsb, apply_once nella forma normale non riporta gli stack di XSB com'erano
# (manca reset_regs in px_qdet) e lascia sullo heap gli argomenti convertiti da Python. Su centinaia
# di migliaia di stati il processo arrivava a ~19 GB. Per questo:
# - tutto ciò che passa dati a XSB usa jns.cmd, che ripristina gli stack;
# - l'unica interrogazione (oh_answer) non ha argomenti e usa truth_vals=PLAIN_TRUTHVALS, il ramo di
#   apply_once che ripristina gli stack. In quel ramo però Janus non rilascia il risultato Python
#   (riferimento in più mai tolto): per limitarne il peso oh_answer restituisce interi piccoli.

import os
import re

import janus_xsb as jns

_loaded = False

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MULVALROOT = os.environ.get("MULVALROOT", os.path.join(os.path.dirname(REPO), "mulval"))
RULES = os.path.join(MULVALROOT, "kb", "interaction_rules.P")
VGYM_RULES = os.path.join(os.path.dirname(__file__), "vulngym_rules.P")
HELPERS = os.path.join(os.path.dirname(__file__), "janus_helpers")

# predicati interrogati, nello stesso ordine delle liste restituite da oh_answer in janus_helpers.P
PREDICATES = ("execCode", "remoteControl", "hasCredentials", "dataCompromised", "dos")


def cmd(pred: str, *args):
    """Esegue pred(*args) in usermod senza restituire dati (fallimento o errore -> RuntimeError)."""
    try:
        ok = jns.cmd("usermod", pred, *args)
    except SystemError as e:
        raise RuntimeError(f"errore prolog in {pred}: {e.__cause__}") from e
    if ok is not True:
        raise RuntimeError(f"{pred} fallito ({ok})")


def subsumptive(rules: str) -> str:
    """':- table p/n.' -> ':- table p/n as subsumptive.'

    Con il tabling per varianti (default) XSB, anche in batched, chiude a volte vuota la tabella di
    una chiamata ground come netAccess('31', any, any) mentre netAccess('31', _, _) ha la risposta:
    sulle topologie tree ~1 stato su 100 era incompleto. Con la sussunzione la chiamata ground legge
    dalla tabella più generale e il problema sparisce. Le regole non hanno negazione, quindi il
    modello minimo calcolato è lo stesso: cambia solo come XSB ci arriva.
    """
    return re.sub(
        r"^:- table ([\w/]+)\s*\.", r":- table \1 as subsumptive.", rules, flags=re.M
    )


def load_mulval(workdir):
    """Replica il caricamento di run.P generato da graph_gen.sh, senza input e senza attack graph."""
    global _loaded
    if _loaded:
        return
    oldfolder = os.getcwd()
    try:
        # generate_dynamic_decl scrive dynamic_decl.gen nella cwd: lavoriamo in una dir temporanea.
        os.chdir(workdir)

        # un secondo load_dyn sostituirebbe le clausole dei predicati già definiti
        # (primitive/1, derived/1, ...): le regole vanno concatenate in un unico file
        with open("running_rules.P", "w") as outfile:
            for fname in (RULES, VGYM_RULES):
                with open(fname) as infile:
                    outfile.write(subsumptive(infile.read()))
                    outfile.write("\n")

        jns.consult(HELPERS)
        cmd("oh_load", MULVALROOT, "running_rules.P")
        _loaded = True
    finally:
        os.chdir(oldfolder)


def assert_facts(facts):
    # ordinati: a parità di insieme di fatti l'ordine delle clausole in XSB è sempre lo stesso
    cmd("oh_assert_list", [list(f) for f in sorted(facts)])


def clear_predicates(facts):
    """Cancella TUTTE le clausole dei predicati che compaiono in facts (non solo quei fatti).

    Da usare solo su predicati che sono puri fatti di input (primitive), mai su predicati con regole.
    """
    cmd(
        "oh_retract_preds",
        [[f, n] for f, n in sorted({(f[0], len(f) - 1) for f in facts})],
    )


def abolish_all_tables():
    cmd("oh_abolish")


def query_all() -> dict[str, set[str]]:
    """Per ogni predicato di PREDICATES gli host H per cui è derivabile (execCode: qualunque privilegio)."""
    try:
        res = jns.apply_once("usermod", "oh_answer", truth_vals=jns.PLAIN_TRUTHVALS)
    except SystemError as e:
        raise RuntimeError(f"errore prolog in oh_answer: {e.__cause__}") from e
    if res["truth"] is not True:
        raise RuntimeError(f"oh_answer fallito o indefinito ({res['truth']})")
    # oh_answer restituisce i nodi come interi (vedi janus_helpers.P): si torna ai nomi-stringa
    return {
        pred: {str(h) for h in hosts} for pred, hosts in zip(PREDICATES, res["return"])
    }
