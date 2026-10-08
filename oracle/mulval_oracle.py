# MulvalOracle: osserva vulnGym giorno per giorno e chiede a MulVAL cosa l'attaccante PUÒ ottenere.
#
# Non modifica mai la simulazione (niente random, niente scritture sull'env). Per ogni episodio registra:
# - db_reachable[t]: secondo MulVAL, a fine giorno t quanti database soddisfano il predicato del goal
#   dell'APT (goal raggiungibile se >= sp.TARGET_GOALS)
# - sim_time_to_goal, mulval_first_reachable, latency, exposure_days: riepilogo dell'episodio
# - violations: conquiste avvenute nel simulatore al giorno t che MulVAL, sullo stato di fine giorno t-1,
#   NON considerava possibili (coerenza simulatore vs gold standard). last_derivable_day = ultimo giorno
#   prima di t in cui MulVAL la considerava possibile: vulnGym controlla le precondizioni quando sceglie il
#   bersaglio ed esegue 1-3 giorni dopo senza ricontrollarle, quindi t-1 - last_derivable_day <= 3 indica una
#   precondizione scaduta durante la preparazione; None = mai possibile nell'episodio (da analizzare).
#
# Ogni risposta di XSB è confrontata con reference.fixpoint (punto fisso calcolato in Python): le
# discrepanze finiscono in xsb_mismatches e devono essere zero perché i risultati siano validi.

import tempfile

import mulval_janus as mj
import reference
import snapshots
from snapshots import sp

GOAL_PREDICATE = {
    "data_exfiltration": "dataCompromised",
    "db_denial_of_service": "dos",
}

# conquista osservata nel simulatore -> predicato MulVAL che doveva essere derivabile il giorno prima
CHECKS = {
    "access": "execCode",
    "credentials": "hasCredentials",
    "data": "dataCompromised",
    "dos": "dos",
}


def sim_state(env) -> dict[str, set[str]]:
    """Cosa ha ottenuto l'attaccante nel simulatore (stessi nomi di nodo dello snapshot)."""
    state = {kind: set() for kind in CHECKS}
    for n, o in env.node_objects.items():
        h = str(n)
        if o.attacker_has_access:
            state["access"].add(h)
        if o.credentials_stolen:
            state["credentials"].add(h)
        if o.data_exfiltrated or o.is_wiped:
            state["data"].add(h)
        if o.is_off:
            state["dos"].add(h)
    return state


class MulvalOracle:
    def __init__(self):
        mj.load_mulval(tempfile.mkdtemp(prefix="mulval_oracle_"))
        self.static: set[tuple] = set()
        self.dynamic: set[tuple] = set()
        self.answer: dict[str, set[str]] | None = None
        self.queries = 0
        self.cache_hits = 0
        self.mismatches: list[
            dict
        ] = []  # risposte XSB diverse dal punto fisso di riferimento
        self.mismatches_before = 0

        self.scenario = None
        self.episodes: list[dict] = []
        self.ep: dict | None = None

    # ------------------------------------------------------------------ MulVAL

    def _sync(self, env) -> dict[str, set[str]]:
        """Allinea i fatti dinamici a env e interroga MulVAL (solo se qualcosa è cambiato)."""
        dynamic = snapshots.get_dynamic(env)
        if self.answer is not None and dynamic == self.dynamic:
            self.cache_hits += 1
            return self.answer

        # Ricarica completa invece del diff: con il diff incrementale l'ordine delle clausole dipende
        # dalla storia degli aggiornamenti e XSB sbagliava ancora 12 stati su 1098; così 0.
        # clear_predicates cancella interi predicati: non deve toccarne nessuno dei fatti statici
        assert not {f[0] for f in dynamic} & {f[0] for f in self.static}
        mj.clear_predicates(self.dynamic)
        mj.assert_facts(dynamic)
        self.dynamic = dynamic
        mj.abolish_all_tables()

        self.answer = mj.query_all()
        self.queries += 1
        self._cross_check(env)
        return self.answer

    def _cross_check(self, env):
        expected = reference.fixpoint(self.static | self.dynamic)
        if expected == self.answer:
            return
        self.mismatches.append(
            {
                "scenario": self.scenario,
                "episode": len(self.episodes),
                "day": env.current_time,
                **{
                    pred: {
                        "missing": sorted(expected[pred] - self.answer[pred]),
                        "extra": sorted(self.answer[pred] - expected[pred]),
                    }
                    for pred in mj.PREDICATES
                    if expected[pred] != self.answer[pred]
                },
            }
        )

    # ------------------------------------------------------------------ hook

    def begin_scenario(self, name: str):
        self.scenario = name
        self.episodes = []
        self.mismatches_before = len(self.mismatches)
        self.ep = None
        self.goal_pred = GOAL_PREDICATE[sp.goal]

    def reset(self, env):
        """Da chiamare dopo env.reset(seed): inizio di un nuovo episodio."""
        self._finish_episode()

        static = snapshots.get_static(env)
        if static != self.static:
            # nuova topologia: si svuota tutto e si ricarica da zero (statici ora, dinamici in _sync)
            mj.clear_predicates(self.dynamic)
            mj.clear_predicates(self.static)
            mj.assert_facts(static)
            self.static = static
            self.dynamic = set()
            self.answer = None
        self.dbs = {str(n) for n, o in env.node_objects.items() if o.zone == "database"}

        self.prev_answer = self._sync(env)
        self.history = [
            self.prev_answer
        ]  # risposta di MulVAL per giorno (oggetti condivisi con la cache)
        self.prev_sim = sim_state(env)
        self.ep = {
            "episode": len(self.episodes),
            "sim_time_to_goal": None,
            "db_reachable": [
                self._db_reachable(self.prev_answer)
            ],  # indice = giorno (0 = dopo reset)
            "violations": [],
        }

    def observe(self, env):
        """Da chiamare dopo env.step(...): fine del giorno env.current_time."""
        if self.ep is None or env.current_time > sp.TIME_LIMIT:
            return  # oltre TIME_LIMIT env.step non cambia nulla
        day = env.current_time
        answer = self._sync(env)
        sim = sim_state(env)

        for kind, pred in CHECKS.items():
            for h in sorted(sim[kind] - self.prev_sim[kind], key=int):
                if h not in self.prev_answer[pred]:
                    self.ep["violations"].append(
                        {
                            "day": day,
                            "last_derivable_day": self._last_day(
                                lambda a: h in a[pred]
                            ),
                            "kind": kind,
                            "node": h,
                            "zone": env.node_objects[int(h)].zone,
                        }
                    )

        if env.time_to_goal_ATTACKER == day:
            # va salvato qui: al reset successivo vulnGym lo riporta a None
            self.ep["sim_time_to_goal"] = day
            if not self._goal(self.prev_answer):
                self.ep["violations"].append(
                    {
                        "day": day,
                        "last_derivable_day": self._last_day(self._goal),
                        "kind": "goal",
                        "node": None,
                        "zone": None,
                    }
                )

        self.ep["db_reachable"].append(self._db_reachable(answer))
        self.prev_answer, self.prev_sim = answer, sim
        self.history.append(answer)

    def end_scenario(self) -> dict:
        """Chiude l'ultimo episodio e restituisce i risultati dello scenario."""
        self._finish_episode()
        return {
            "experiment": sp.EXPERIMENT,
            "apt": sp.APT_NAME,
            "goal": sp.goal,
            "goal_predicate": self.goal_pred,
            "target_goals": sp.TARGET_GOALS,
            "scenario": self.scenario,
            "xsb_mismatches": self.mismatches[self.mismatches_before :],
            "episodes": self.episodes,
        }

    # ------------------------------------------------------------------ helper

    def _last_day(self, holds) -> int | None:
        """Ultimo giorno già osservato (fino a t-1) in cui holds(risposta di MulVAL) era vero."""
        return next(
            (d for d in range(len(self.history) - 1, -1, -1) if holds(self.history[d])),
            None,
        )

    def _db_reachable(self, answer) -> int:
        return len(answer[self.goal_pred] & self.dbs)

    def _goal(self, answer) -> bool:
        return self._db_reachable(answer) >= sp.TARGET_GOALS

    def _finish_episode(self):
        if self.ep is None:
            return
        ep = self.ep
        reachable = [n >= sp.TARGET_GOALS for n in ep["db_reachable"]]
        first = next((day for day, r in enumerate(reachable) if r), None)
        sim_goal = ep["sim_time_to_goal"]
        ep["mulval_first_reachable"] = first
        ep["exposure_days"] = sum(reachable[1:])
        ep["days"] = len(reachable) - 1
        ep["latency"] = (
            sim_goal - first if sim_goal is not None and first is not None else None
        )
        self.episodes.append(ep)
        self.ep = None
