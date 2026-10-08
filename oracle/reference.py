# Valutatore di riferimento indipendente da XSB: calcola in Python il modello minimo (punto fisso)
# delle regole MulVAL + vulngym_rules.P che possono scattare sui fatti emessi da snapshots.py.
#
# Serve a controllare l'oracolo: a ogni stato la risposta di XSB deve coincidere con questa.
# Le regole MulVAL non riportate qui hanno premesse che lo snapshot non emette mai
# (localExploit, clientProgram, nfsMounted, hasAccount, ...), quindi non possono scattare.
#
# Corrispondenza con le regole (tutte le porte e i protocolli sono 'any', vedi snapshots.ANY):
#   netAccess(H)      :- attackerLocated(Z), hacl(Z, H)                    direct network access
#   netAccess(H2)     :- execCode(H1), hacl(H1, H2)                        multi-hop access
#   execCode(H)       :- vulExists(H, privEscalation), networkServiceInfo(H), netAccess(H)
#                                                                          remote exploit of a server program
#   execCode(H)       :- attackerHasAccess(H)                              current attacker foothold
#   execCode(H2)      :- hasCredentials(H1), hacl(H1, H2)                  lateral movement
#   remoteControl(H)  :- vulExists(H, privEscalation), networkServiceInfo(H), netAccess(H)
#   remoteControl(H)  :- attackerHasAccess(H), exploitedVul(H, V), vulExists(H, V, privEscalation)
#   hasCredentials(H) :- credentialsStolen(H) ; remoteControl(H)
#   dataCompromised(H):- dataExfiltrated(H) ; dataWiped(H) ; remoteControl(H)
#   dos(H)            :- nodeOff(H) ; vulExists(H, dos), networkServiceInfo(H), netAccess(H)


def fixpoint(facts: set[tuple]) -> dict[str, set[str]]:
    by_pred: dict[str, set[tuple]] = {}
    for f in facts:
        by_pred.setdefault(f[0], set()).add(f[1:])

    def hosts(pred):
        return {args[0] for args in by_pred.get(pred, ())}

    located = hosts("attackerLocated")
    access = hosts("attackerHasAccess")
    hacl = {(a, b) for a, b, _proto, _port in by_pred.get("hacl", ())}
    neighbours: dict[str, set[str]] = {}
    for a, b in hacl:
        neighbours.setdefault(a, set()).add(b)

    # vulExists/5 = vulExists/3 + vulProperty/3 (regola di MulVAL); serve anche il prodotto
    # installato (networkServiceInfo) dato che la regola di exploit li unifica su Software
    consequences: dict[str, set[str]] = {}
    for cve, _range, cons in by_pred.get("vulProperty", ()):
        consequences.setdefault(cve, set()).add(cons)
    services = {(h, sw) for h, sw, *_ in by_pred.get("networkServiceInfo", ())}
    privesc, dos_vuln, privesc_cve = set(), set(), set()
    for h, cve, sw in by_pred.get("vulExists", ()):
        cons = consequences.get(cve, set())
        if "privEscalation" in cons:
            privesc_cve.add((h, cve))
            if (h, sw) in services:
                privesc.add(h)
        if "dos" in cons and (h, sw) in services:
            dos_vuln.add(h)

    foothold = {
        h
        for h, cve in by_pred.get("exploitedVul", ())
        if h in access and (h, cve) in privesc_cve
    }
    credentials = hosts("credentialsStolen")

    # attackerLocated(H) dà anche netAccess(H) (direct on-host access)
    net, execc, rc, hc = set(located), set(access), set(foothold), set()
    while True:
        before = (len(net), len(execc), len(rc), len(hc))
        for src in located | execc:
            net |= neighbours.get(src, set())
        new_rc = privesc & net
        rc |= new_rc
        execc |= new_rc
        hc = credentials | rc
        for src in hc:
            execc |= neighbours.get(src, set())
        if (len(net), len(execc), len(rc), len(hc)) == before:
            break

    return {
        "execCode": execc,
        "remoteControl": rc,
        "hasCredentials": hc,
        "dataCompromised": hosts("dataExfiltrated") | hosts("dataWiped") | rc,
        "dos": hosts("nodeOff") | (dos_vuln & net),
    }
