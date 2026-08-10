# Briar — Audit méthodique & plan de correction

> Audit du 2026-07-10 (v0.4.39). Basé sur 3 lectures profondes indépendantes de tout le code
> (détection / perf-core / providers-reports-web). Chaque point est à re-vérifier au moment du fix.

## Constat global

Briar **tourne** de bout en bout (32 agents, pipeline concurrent, rapports, dashboard, PDF), mais
il **ne confirme aucune vraie vuln** et un `--deep` prend **1h20**. Trois causes racines :

1. **Le scan ne cible jamais la vraie surface d'attaque.** Le crawler trouve `/listproducts.php?cat=1`
   mais les agents ne reçoivent que l'URL racine + des noms de params génériques → le param vulnérable
   `cat` n'est jamais injecté. `merge_params`/`params_from_url`/`batch_send` sont écrits mais **branchés nulle part**.
2. **Le temps est mangé par 31 appels LLM sérialisés** (1 par agent, même sans finding) dans Ollama
   (modèle unique) → 15-45 min de LLM pur avant même le HTTP série sur cible lente.
3. **Le validateur "confirme du vent"** : `confirmed=True` sur n'importe quelle réponse HTTP, sans
   rejouer la détection, et sur l'URL de base — donc soit faux positifs, soit jamais de vraie preuve.

Plus : des blocages de déploiement (matplotlib crashe l'install de base), un dashboard qui ne charge
pas les clés API, du XSS stocké dans le rapport HTML, et une pluie de faux positifs heuristiques.

---

## Plan par phases (ordre = impact × dépendance)

### Phase 0 — Débloquer l'install/import (sinon rien ne marche en prod)
- [ ] `charts/generator.py:2` — matplotlib importé au top-level mais en extra `[full]` → **tout scan crashe** sur install de base. Lazy-import + try/except, ou passer matplotlib en dep core.
- [ ] `web.py:566`, `html_report.py:229` — backslash dans f-string → **SyntaxError sur Python 3.10/3.11** alors que `requires-python>=3.10`. Corriger les f-strings OU monter à `>=3.12`.
- [ ] `pyproject.toml` — déclarer `markdown` (utilisé par web/expert) ; `word()/excel()` renvoient une string d'erreur affichée comme un chemin de rapport (`cli.py:435`) → distinguer succès/échec.
- [ ] `cli.py:55` — `@click.version_option(version="0.4.32")` figé → `version=__version__`.

### Phase 1 — Moteur de DÉTECTION (le vrai "0 confirmed")
- [ ] `agents/__init__.py:170` — router chaque **endpoint crawlé** (recon `endpoints`/`urls_sample`) vers les agents-params, pas juste l'URL racine (scan par URL, pas par domaine).
- [ ] agents-params (`injection`,`xss`,`ssrf`,`traversal`,`nosql`,`ssti`,`crlf`,`open_redirect`) — remplacer les listes génériques par `merge_params(url, DEFAULTS)` pour tester les **vrais params** de l'URL.
- [ ] `core/http.py:42` — `send_payload` **ajoute** le param au lieu d'écraser un param existant (`?cat=1&id=payload` laisse `cat=1` bénin) → réécrire la query pour écraser la valeur ciblée.
- [ ] tous les agents-params — le call LLM final (`analyze_endpoint`) n'est **pas gardé** : s'il lève (provider down), l'agent crashe et **jette les `real_findings` déjà prouvés** → try/except + rattacher real_findings quoi qu'il arrive. (injection.py:96 déjà corrigé cette session.)
- [ ] `core/validator.py` — `validate()` confirme sur n'importe quelle réponse et tape l'URL de base ; `validate_all()` ne regarde que `param`/`payload` au top-niveau et rate les `real_findings` → rejouer la **détection** sur `finding['url']` et descendre dans `real_findings`.
- [ ] `agents/__init__.py:112` — `run_agent` pop `recon_data` mais ne le reforwarde jamais → **planner mort** ("No recon data available"). Réinjecter dans kwargs.

### Phase 2 — PERF (1h20 → minutes)
- [ ] **LEVIER #1** : ne lancer le LLM que si `real_findings` non vide (ou une synthèse LLM unique en fin de scan) → passe de ~31 appels à ~2-5. Impact -60 à -80%.
- [ ] Câbler `HTTPClient.batch_send` dans les agents à double boucle (traversal 176 req, injection 144, ssrf 100…) → série → parallèle. Impact -70% sur la part HTTP.
- [ ] Poser `BRIAR_HTTP_TIMEOUT≈5s` dans le flux de scan (cli/web/worker) — lu mais jamais posé, donc inactif. Baisser aussi le timeout Ollama (120s → ~45s) + configurable.
- [ ] Gate "cible joignable" après recon (`agents/__init__.py`) — si recon échoue/cible down, **abandonner** au lieu de 30 agents × 100 req × timeout.
- [ ] `worker.py:30` — exécution série sans `recon_data` ni concurrence → utiliser `run_scan_agents`.

### Phase 3 — FAUX POSITIFS (crédibilité du rapport)
- [ ] `injection.py:64,69` — boolean `abs(len-baseline)>100` sur baseline d'un autre param + time-based sur 1 requête → baseline par param + double requête (1=1 vs 1=2) + répétition pour le timing.
- [ ] `idor.py:96` / `authz.py:51` — "contenu différent" = IDOR (comportement normal) → vrai test multi-session (accès sans/avec session).
- [ ] `auth.py:102` — "weak creds" si 200 sans mot "error" → comparer à un baseline d'échec connu + vérif cookie/redirection.
- [ ] `rce.py:31,78` — command injection sur le mot "Linux", SSTI sur "49" n'importe où → exiger la sortie liée au payload (reprendre la logique de `ssti.py`).
- [ ] `gitbackup.py:51` — exposition flaggée sur 301/302/403 → restreindre à 200 + marqueur dans le corps.
- [ ] `csrf.py:30` / `upload.py:48` — tout form POST = CSRF, tout upload 200 = "fichier dangereux accepté" → vérifier acceptation cross-origin réelle / refetch du fichier uploadé.
- [ ] `confidence.py:22` — tout `real_findings` → 75/"Probable" quel que soit le type de preuve → pondérer selon la qualité de preuve, pas sa présence.

### Phase 4 — PROVIDERS & robustesse
- [ ] 8 providers OpenAI-compat — **aucun timeout** (hang jusqu'à ~600s) ni retry → ajouter `timeout=` + retry léger + uniformiser la gestion d'erreur (together/custom/xai/google/openrouter ne l'encapsulent pas).
- [ ] `google.py:12` — n'envoie que le dernier message + ignore `max_tokens` ; `custom.py:7` — lit `CUSTOM_BASE_URL` alors que setup écrit `CUSTOM_ENDPOINT` ; `ollama.py:7` — ignore `OLLAMA_MODEL/OLLAMA_HOST` → config sauvegardée ignorée.
- [ ] `web.py:617` — `launch_scan` ne charge jamais `load_saved_config()` → **scans dashboard sans clés API** (silencieux) pour tout provider payant.

### Phase 5 — Sécurité & polish
- [ ] `html_report.py` (entier) + `web.py:474` scan_detail — analysis/url/poc injectés sans `html.escape` ni CSP → **XSS stocké** → échapper + `<meta CSP>` (comme `expert.py` le fait déjà).
- [ ] Bugs divers : `jwt.py:63` `alg.lower()` crashe sur `alg:null` → `str(alg or "")` ; `injection.py:115` `parse_qs` non importé ; `cli.py:466` message resume pas en f-string.
- [ ] Qualité : `except:` nus partout → `except Exception` + log ; DRY `filter_noise` (réimplémenté inline dans cli) ; `animation.py` code mort + `sylph.render()` qui bave dans la zone live rich ; noms de fichiers rapports au timestamp (pas juste la date) ; versions en dur dans html_report/slides.

---

## Ordre d'exécution recommandé

**Phase 0** (rapide, débloque tout) → **Phase 1** (fait apparaître les vrais confirmed) →
**Phase 2** (rend le scan utilisable) → **Phase 3** (nettoie les faux positifs) →
**Phase 4-5** (fiabilité/sécu). Chaque phase testable indépendamment. Valider sur `testphp.vulnweb.com`
après Phase 1+2 (doit sortir la SQLi de `cat` en confirmed).
