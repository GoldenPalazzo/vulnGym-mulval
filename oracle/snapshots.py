import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "code"))

import simulation_parameters as sp
import networkx as nx

REMOTE_CONTROL = "remote_control"  # macro.REMOTE_CONTROL
DOS = "dos"  # macro.DOS
ANY = "any"  # vulnGym non modella protocolli e porte


def entry_points(env) -> set[int]:
    """Nodi attaccabili direttamente da internet (DQNAttacker._select_target_node, fase START)."""
    entries = set(env.starting_nodes)
    if sp.apt_phishing:
        entries |= {
            n
            for n, o in env.node_objects.items()
            if o.zone == "internal" and o.phishing
        }
    return entries


def apt_can_exploit(vuln, node) -> bool:
    """Decisione di modellazione 1: probabilità di successo > 0 in calculate_success_probability
    (CVE nell'arsenale KEV+Metasploit OPPURE nodo con un prodotto dell'APT)."""
    return vuln.cve_id in sp.apt_vulns or any(
        p in sp.apt_products for p in node.products
    )


def get_static(env) -> set[tuple]:
    facts: set[tuple] = set()
    net: nx.Graph = env.network

    facts.add(("attackerLocated", "internet"))

    for n in entry_points(env):
        facts.add(("hacl", "internet", str(n), ANY, ANY))

    # Il grafo non è orientato: edges() dà ogni coppia una sola volta, servono entrambi i versi.
    for a, b in net.edges():
        facts.add(("hacl", str(a), str(b), ANY, ANY))
        facts.add(("hacl", str(b), str(a), ANY, ANY))

    for n, o in env.node_objects.items():
        for p in o.products:
            facts.add(("networkServiceInfo", str(n), p, ANY, ANY, "user"))

    return facts


def get_dynamic(env) -> set[tuple]:
    facts: set[tuple] = set()

    for n, o in env.node_objects.items():
        h = str(n)

        if o.attacker_has_access:
            facts.add(("attackerHasAccess", h))
        if o.credentials_stolen:
            facts.add(("credentialsStolen", h))
        if o.data_exfiltrated:
            facts.add(("dataExfiltrated", h))
        if o.is_wiped:
            facts.add(("dataWiped", h))
        if o.is_off:
            facts.add(("nodeOff", h))

        # o.vulnerabilities contiene solo le CVE già rivelate (incluse le patchate).
        for v in o.vulnerabilities:
            if v.patched:
                continue
            foothold = v.exploited and o.attacker_has_access
            # Nodo spento: niente nuovi exploit (is_valid_node lo esclude), ma la post-exploitation
            # su un accesso già ottenuto resta possibile (_valid_post_actions_for_node non controlla is_off).
            if o.is_off and not foothold:
                continue
            if not (foothold or apt_can_exploit(v, o)):
                continue

            for p in set(v.products) & set(o.products):
                facts.add(("vulExists", h, v.cve_id, p))

            if REMOTE_CONTROL in v.vulnerability_type:
                facts.add(("vulProperty", v.cve_id, "remoteExploit", "privEscalation"))
            if DOS in v.vulnerability_type:
                facts.add(("vulProperty", v.cve_id, "remoteExploit", "dos"))

            if v.exploited and o.attacker_has_access:
                facts.add(("exploitedVul", h, v.cve_id))

    return facts


def _atom(value) -> str:
    """Atomo Prolog sempre quotato: 'oracle:oracle' senza apici sarebbe una chiamata di modulo."""
    s = str(value).replace("\\", "\\\\").replace("'", "\\'")
    return f"'{s}'"


def write_prolog_file(facts, path, goal: str | None = None):
    """Scrive i fatti come file .P per graph_gen.sh (opzionale: attackGoal, es. 'execCode(_,_)')."""
    with open(path, "w") as f:
        if goal is not None:
            f.write(f"attackGoal({goal}).\n")
        for pred, *args in sorted(facts):
            f.write(f"{pred}({', '.join(_atom(a) for a in args)}).\n")
