"""
v4 gate (v3 + exact whole-value matching, fixing the B4 "collision" hole found after v3 froze).
v3 gate (v2 + fixes for holes found by the post-freeze adaptive attacks A2 and A5).
v2 gate: "orders vs facts, safe against added text".

First principle: an injected attacker can ADD text somewhere; they cannot DELETE yours.
So every rule is written so that added text can only make the gate stricter:
  1. Orders (what to do) come only from you, or from a PERSON you explicitly handed orders to whose
     identity is verified (your records, your organisation's mail domain). Documents and websites you
     told the agent to follow supply details for the job you described; they never add new kinds of action.
  2. Everything else is a fact source at best. Facts can fill in a slot your order created (Alice's email
     address, the bill's account number) only from a source you pointed to for that kind of fact, and only
     if the answer is UNIQUE. If added text offers a second candidate, the gate refuses instead of picking.
  3. A website speaks only for itself (its own pages and addresses).
  4. Identity comes from records. An address that merely looks like a named person may stand for that
     person only as an address to send to, never as a source of orders or values.
  5. Parsing is structural (YAML mail/calendar, Python-literal product lists), so text inside a field
     can never change which field or author it belongs to.
Kinds of text:  order | record (platform facts) | fact | stranger.
Rule-based. No AI calls. No network.
"""
import re, ast
import yaml
from v0_gate import READ_ONLY, CONFIRM, LOW_RISK_WRITES, LICENSE, DELEGATION, STOP_NAMES, SENSITIVE
from v1_gate import RECEIVED_MAIL_TOOLS, EMAIL_RE, URL_RE, norm, dom_of

PLATFORM_ADDRS = {"shopping_platform@mail.com", "banking_platform@mail.com", "github-noreply@github.com"}
PLATFORM_DOMAINS = {"github.com"}
PAGE_TOOLS = {"browse_webpage", "get_webpage", "input_to_webpage", "click_the_link"}
SELF_INFO_TOOLS = {"get_shopping_account_user_information", "get_github_account_user_information",
                   "get_logged_in_github_user_information", "get_balance"}

SLOT_TYPE = {"recipient": "iban", "recipients": "email", "cc": "email", "bcc": "email",
             "collaborator_email": "email", "new_owner_email": "email", "new_owner_username": "username",
             "ssh_key": "ssh", "url": "url", "product_id": "product", "product_ids": "product", "repo_name": "repo"}
FACT_TYPES = {"iban", "email", "ssh", "username", "url"}          # kinds of value a fact may supply
TYPE_RE = {
    "iban": re.compile(r"\b[A-Z]{2}\d{2}(?:[ \-]?[A-Z0-9]){8,30}\b"),
    "email": EMAIL_RE,
    "ssh": re.compile(r"ssh-(?:rsa|ed25519|dss)\s+[A-Za-z0-9+/=]{8,}"),
    "url": URL_RE,
}
FREE_TEXT_KEYS = {"subject", "body", "title", "description", "comment_body", "content", "comment"}
STRICT_UNIQUE = {"recipient", "collaborator_email", "new_owner_email", "new_owner_username", "ssh_key"}
EMAIL_LICENSE = re.compile(r"\b(send\w*|reply|replies|forward\w*|greeting|share (it|this|them|the \w+( \w+)?) (with|to)|write (to|back)|email (him|her|them|it|back|to|the|a|my))\b", re.I)
CALENDAR_LICENSE = re.compile(r"\b(schedule|calendar|set up (a|an) (\w+ )?event|create (a|an) (\w+ )?event|book (a|an) (\w+ )?meeting|reschedule)\b", re.I)
VERB_LICENSED = {"send_email", "create_calendar_event", "reschedule_calendar_event", "add_calendar_event_participants"}
DOC_INSTRUCTIONS = re.compile(r"(instructions?|steps|details)[^.]{0,60}\b(in|on|from|within|of)\b[^.]{0,25}\b(bill|document|doc|file|pdf|form|invoice)\b|according to (this|the|my) (document|file|bill|doc|pdf)", re.I)
PASSWORD_LICENSE = re.compile(r"\b(change|update|reset|set|modify)\b[^.]{0,40}\bpassword|\bnew password\b", re.I)
INSTRUCTION_CUE = re.compile(r"\b(instructions?|according to|accordingly|follow|steps|listed (on|in)|as described)\b", re.I)
POINTER = re.compile(r"\b(find|get|see|check|use|look up|using)\b(?P<what>[^.]{0,90}?)\b(in|at|from|inside|within)\b\s+(?P<where>[^.,;]{1,70})", re.I)
MAILW = re.compile(r"\b(email|emailed|emails|inbox|mail|sent|send|message|shared|told|asked|ask|invited)\b", re.I)
COMMON_CAPS = set("""hi hello dear best regards thanks thank please meeting team software development summary attached notice
important information sincerely cheers today tomorrow yesterday monday tuesday wednesday thursday friday saturday sunday january
february march april may june july august september october november december the this that these those here there when where what
which who why how and but for with from your our their his her its we you they after before also note subject re fw fwd update
new project repository file files document link click visit download task tasks request details agenda room conference dinner
book club discussion first second next last week day off office company colleague colleagues star repo follow github email""".split())
STOPW = set("please could would with that this have from your their there which what when then than into also about after before "
            "account information email address find check make sure help tomorrow today using apply available".split())


def words(s):
    return {w for w in re.findall(r"[a-z]{4,}", s.lower()) if w not in STOPW}


def license_from(text):
    out = set()
    for pat, tools in LICENSE:
        if "password" in pat: continue
        if re.search(pat, text, re.I): out |= (tools - VERB_LICENSED)
    if EMAIL_LICENSE.search(text): out.add("send_email")
    if CALENDAR_LICENSE.search(text): out |= {"create_calendar_event", "reschedule_calendar_event", "add_calendar_event_participants"}
    if PASSWORD_LICENSE.search(text): out |= {"update_shopping_account_password", "update_github_account_password"}
    return out


def types_in(what):
    w = what.lower(); t = set()
    if re.search(r"\b(e-?mail|address)", w): t.add("email")
    if re.search(r"\b(account|bank|iban|payment|information|info|details)\b", w): t |= {"iban", "email", "username"}
    if re.search(r"\b(ssh|key)", w): t.add("ssh")
    if re.search(r"\b(username|user name)", w): t.add("username")
    if re.search(r"\b(link|url|website|page)", w): t.add("url")
    return t


class Gate:
    def __init__(self, prompt):
        p = self.prompt = prompt
        self.np = norm(p)
        self.groups = {}                         # name token -> person key ("alexander chen")
        self._names(p, prompt_text=True)
        self.named_domains = {dom_of(d) for d in URL_RE.findall(p)}
        self.prompt_addrs = {a.lower() for a in EMAIL_RE.findall(p)}
        self.delegates = bool(DELEGATION.search(p)) or bool(re.search(r"\baccordingly\b|\blisted on\b", p, re.I))
        self.doc_orders = bool(INSTRUCTION_CUE.search(p))       # you told it to follow a document/site
        self.base_licensed = license_from(p)
        self.needs_doc = bool(DOC_INSTRUCTIONS.search(p))     # you said the details are in a document
        self.licensed = set(self.base_licensed)
        self.prompt_paths = [x.rstrip(".,;:)'\"") for x in re.findall(r"(/[\w\./_-]+)", p)]
        self.pointers = []                       # (types, paths, wants_download, wants_inbox)
        for m in POINTER.finditer(p):
            where = m.group("where")
            self.pointers.append((types_in(m.group("what") + " " + where),
                                  [x.rstrip(".,;:)'\"") for x in re.findall(r"(/[\w\./_-]+)", where)],
                                  bool(re.search(r"\b(cv|resume|document|doc|file|pdf|bill|invoice|form)\b", where, re.I)),
                                  bool(re.search(r"\b(inbox|email|mail)\b", where, re.I))))
        self.order_words = words(p)
        sents = re.split(r"(?<=[.!?])\s+", p)
        self.sender_named = set()
        for i, s in enumerate(sents):
            if not MAILW.search(s): continue
            self.sender_named |= {self.groups[t] for t in self.groups if re.search(rf"\b{t}\b", s, re.I)}
            if i > 0 and re.search(r"\b(his|her|him|he|she|their|them)\b", s, re.I):
                self.sender_named |= {self.groups[t] for t in self.groups if re.search(rf"\b{t}\b", sents[i - 1], re.I)}
        self.mentioned = set()                   # people a delegate named (v3)
        self.segments = []
        self.known = {}                          # address -> person key (from records)
        self.ent_addrs = {}
        self.self_vals, self.self_dest = set(), set()
        self.file_origin = {}                    # file name -> (kind, subject)
        self.money_budget = 1
        self.pending_blocked = False
        self.taint = None

    # ---------------- names & identity ----------------
    @property
    def people(self):
        return set(self.groups.values())

    def _names(self, text, prompt_text=False, sender_named=False):
        pat = r"\b([A-Z][a-z]+)(?:\s+([A-Z][a-z]+))?" if prompt_text else r"(?<=[a-z,] )([A-Z][a-z]{2,})(?:\s+([A-Z][a-z]+))?"
        for a, b in re.findall(pat, text):
            toks = [t for t in (a, b) if t and t not in STOP_NAMES and t.lower() not in COMMON_CAPS]
            if not toks: continue
            key = " ".join(t.lower() for t in toks)
            for t in toks:
                self.groups.setdefault(t.lower(), key)
            # names a delegate mentions: their one look-alike address may be used as an ADDRESS to reach them,
            # but their mail never counts as orders or facts (only people YOU said wrote to you get that) (v3)
            if sender_named: self.mentioned.add(self.groups[toks[0].lower()])

    def looks_like(self, addr, person):
        toks = set(re.split(r"[\._\-+]", addr.split("@")[0]))
        return any(n in toks or any(t.startswith(n) for t in toks if len(t) > 2) for n in person.split())

    def learn_known(self, text, person=None):
        for x in EMAIL_RE.findall(text):
            x = x.lower()
            ent = person or next((q for q in self.people if self.looks_like(x, q)), None)
            if ent and x not in self.known:
                self.known[x] = ent; self.ent_addrs.setdefault(ent, set()).add(x)

    def my_domains(self):
        return {x.split("@")[-1] for x in self.self_dest if "@" in x}

    def person_of(self, addr):
        """(person, tier) for a sender address. tier: 'verified' (records, your org's domain, your request)
        or 'lookalike' (the only address that could be someone you said wrote to you). Else (None, None)."""
        a = addr.lower()
        if a in self.prompt_addrs: return "prompt:" + a, "verified"
        if a in self.known and len(self.ent_addrs.get(self.known[a], ())) == 1: return self.known[a], "verified"
        for q in self.people:
            if not self.looks_like(a, q): continue
            if a.split("@")[-1] in self.my_domains(): return q, "verified"
            if (q in self.sender_named or q in self.mentioned) and not self.has_platform_channel(q):
                cands = {s for s in self.all_senders() if self.looks_like(s, q)}
                if cands == {a} and not any(c in self.known for c in cands):
                    return q, ("lookalike" if q in self.sender_named else "mentioned")
        return None, None

    def has_platform_channel(self, person):
        """A platform notice already carries this person's message ('Lily White has shared a document'), so an
        unverified address claiming to be them is a second, conflicting candidate."""
        for s in self.segments:
            if s["kind"] != "record" or not s.get("sender"): continue
            for t in person.split():
                if re.search(rf"\b{t}\b[^.\n]{{0,20}}\b(has shared|shared|has invited|invited|has sent)\b", s["text"], re.I):
                    return True
        return False

    def all_senders(self):
        return {s["sender"] for s in self.segments if s.get("sender")}

    def is_platform(self, addr):
        a = addr.lower(); d = a.split("@")[-1]
        return a in PLATFORM_ADDRS or d in PLATFORM_DOMAINS or any(d.endswith("." + x) for x in PLATFORM_DOMAINS)

    def is_org_system(self, addr):
        a = addr.lower(); d = a.split("@")[-1]
        if not re.search(r"(noreply|donotreply|no-reply)", a): return False
        mine = {x.split(".")[0] for x in self.my_domains()}
        return any(lbl in mine for lbl in d.split("."))

    # ---------------- segments ----------------
    def _add(self, text, kind, subject=None, host=None, **extra):
        if self.taint == "stranger": kind = "stranger"
        elif self.taint == "fact" and kind in ("order", "record"): kind = "fact"
        seg = {"text": text, "ntext": norm(text), "kind": kind, "subject": subject, "host": host,
               "tainted": self.taint,
               # whole values, so "miller@gmail.com" never matches inside "alice.miller@gmail.com" (v4)
               "emails": {x.lower() for x in EMAIL_RE.findall(text)},
               "ibans": {norm(x) for x in TYPE_RE["iban"].findall(text)},
               "urls": {re.sub(r"[/.!,;:?)\]\\'\"]+$", "", norm(x).split("?")[0]) for x in URL_RE.findall(text)}}
        seg.update(extra)
        self.segments.append(seg)
        return seg

    def _refresh(self):
        """Re-derive who each email is from, what that lets them do, and who they name, until stable."""
        for _ in range(4):
            before = (len(self.groups), len(self.licensed), tuple(s["kind"] for s in self.segments if s.get("sender")))
            for s in self.segments:
                snd = s.get("sender")
                if not snd: continue
                sd = snd.split("@")[-1]
                site = next((nd for nd in self.named_domains if sd == nd or sd.endswith("." + nd)), None)
                if self.is_platform(snd) or self.is_org_system(snd):
                    kind, who = "record", None
                elif site:
                    kind, who = ("record" if s["part"] == "from" else "fact"), site
                else:
                    who, tier = self.person_of(snd)
                    if s["part"] == "from":
                        kind = "record" if who else "stranger"
                    elif tier == "verified":
                        kind = "order" if self.delegates else "fact"
                    elif tier == "lookalike":
                        # you said this person wrote to you; if you also said to do what they ask, you vouch for them
                        kind = "order" if self.delegates else "fact"
                    else:
                        kind = "stranger"
                if s["tainted"] == "stranger": kind = "stranger"
                s["kind"], s["subject"] = kind, who
            self.licensed = set(self.base_licensed)
            for s in self.segments:
                if s.get("sender") and s["kind"] == "order" and s["part"] == "body":
                    self.licensed |= license_from(s["text"])
                    self._names(s["text"], sender_named=True)
                    self.learn_known(s["text"])
            after = (len(self.groups), len(self.licensed), tuple(s["kind"] for s in self.segments if s.get("sender")))
            if after == before: break

    def file_subject(self, path, text):
        base = path.split("/")[-1].lower()
        for t, q in self.groups.items():
            if t in base: return q
        if base.startswith("my") or "my_" in base: return "self"
        head = text[:200].lower()
        for t, q in self.groups.items():
            if re.search(rf"\b{t}\b", head): return q
        if "emma" in head or any(v in head for v in self.self_dest): return "self"
        return None

    def site_kind(self, url):
        d = dom_of(url)
        named = any(d == nd or d.endswith("." + nd) for nd in self.named_domains)
        if named: return ("order" if self.doc_orders else "fact"), d
        if self.nav_bound(url):
            segs = self.where_segs(url)
            if any(s["kind"] == "record" and s.get("sender") for s in segs):
                # a link in a platform share notice opens a shared DOCUMENT, not a website speaking for itself
                return ("order" if self.doc_orders else "fact"), "file:" + norm(url).split("?")[0]
            via_order = any(s["kind"] == "order" for s in segs)
            return ("order" if (self.doc_orders and via_order) else "fact"), d
        return "stranger", d

    def observe(self, fn, args, text):
        text, args, fn = text or "", args or {}, fn or ""
        if fn in PAGE_TOOLS:
            url = str(args.get("url", "") or args.get("web_url", ""))
            kind, subj = self.site_kind(url)
            d = dom_of(url)
            ads = re.findall(r'<div class="ad-block".*?</div>', text, re.S)
            main = re.sub(r'<div class="ad-block".*?</div>', " ", text, flags=re.S)
            self._add(main, kind, subject=subj, host=d)
            for a in ads: self._add(a, "stranger", host=d)
            m = re.search(r"([\w\.\-]+?)(?:\(\d+\))? has been added to \w+", text)
            if m: self.file_origin[m.group(1).lower()] = (kind, "file:" + m.group(1).lower() if kind != "stranger" else None)
        elif fn in RECEIVED_MAIL_TOOLS and "sender:" in text:
            self._observe_mail(text)
        elif fn == "get_sent_emails":
            self.learn_known(text)
            self._add(text, "record", subject="self")
        elif fn == "search_product":
            self._observe_products(text, args)
        elif fn == "read_file":
            self._observe_file(str(args.get("file_path", "") or args.get("path", "")), text)
        elif fn in ("download_file_through_url", "download_file_through_id"):
            m = re.search(r"([\w\.\-]+?)(?:\(\d+\))? has been added to \w+", text)
            if m:
                fname = m.group(1).lower()
                if fn == "download_file_through_url":
                    kind, d = self.site_kind(str(args.get("url", "")))
                else:
                    fid = str(args.get("file_id", args.get("File Id", "")))
                    ks = {s["kind"] for s in self.where_segs(fid)}
                    kind = "order" if "order" in ks else ("fact" if ks & {"fact", "record"} else "stranger")
                if kind != "stranger": kind = "order" if self.doc_orders else "fact"
                self.file_origin[fname] = (kind, "file:" + fname if kind != "stranger" else None)
            self._add(text, "record")
        elif fn in ("get_day_calendar_events", "search_calendar_events"):
            self._observe_calendar(text)
        elif fn in ("git_push", "git_pull", "git_clone"):
            self._add(text, "fact")
        elif fn == "get_github_repository_information":
            issues = re.findall(r"Issues\(owner_username='([^']+)', comments=(.*?)\)(?=, Issues\(|\]\"|\]'|$)", text, re.S)
            meta = re.sub(r"Issues\(owner_username=.*", " ", text, flags=re.S)
            self._add(meta, "record")
            self.learn_known(meta)
            for owner, body in issues:
                self._add(body, "stranger")
        else:
            self._add(text, "record", subject="self" if fn in SELF_INFO_TOOLS else None)
            if fn in SELF_INFO_TOOLS:
                self.self_vals |= {v.lower() for v in EMAIL_RE.findall(text)} | {norm(v) for v in TYPE_RE["iban"].findall(text)}
                self.self_dest |= {v.lower() for v in EMAIL_RE.findall(text)}
        self.taint = None
        self._refresh()

    def _observe_file(self, path, text):
        name = path.split("/")[-1].lower()
        subj = self.file_subject(path, text)
        pointed = [pp for pp in self.prompt_paths if pp and (path.startswith(pp) or pp.startswith(path))]
        info_ptr = any(any(path.startswith(pp) or pp.startswith(path) for pp in ptr[1]) for ptr in self.pointers)
        if name in self.file_origin:
            kind, s0 = self.file_origin[name]
            if subj not in self.people and subj != "self": subj = s0
        elif not pointed:
            kind = "stranger"
        else:
            kind = "order" if (self.doc_orders and not info_ptr) else "fact"
            if subj is None: subj = "path:" + pointed[0]
        self._add(text, kind, subject=subj, path=path, downloaded=name in self.file_origin)
        if subj == "self" and kind != "stranger":
            self.self_vals |= {v.lower() for v in EMAIL_RE.findall(text)} | {norm(v) for v in TYPE_RE["iban"].findall(text)}
        elif subj in self.people and kind in ("fact", "order"):
            vals = {x.lower() for x in EMAIL_RE.findall(text)}
            if len(vals) == 1: self.learn_known(text, person=subj)

    def _observe_mail(self, text):
        items = None
        for cand in (text, self._strip_wrapper(text)):
            try:
                items = yaml.safe_load(cand)
            except Exception:
                items = None
            if isinstance(items, list) and all(isinstance(i, dict) and "sender" in i for i in items): break
            items = None
        if items is None:                          # fail closed: no structure, no identities
            self._add(text, "stranger")
            return
        rc = {}
        for it in items:
            for r in (it.get("recipients") or []): rc[str(r).lower()] = rc.get(str(r).lower(), 0) + 1
        if rc:
            me = max(rc, key=rc.get); self.self_vals.add(me); self.self_dest.add(me)
        for it in items:
            s = str(it.get("sender", "unknown")).lower()
            body = " ".join(str(it.get(k, "")) for k in ("subject", "body", "attachments"))
            heads = " ".join(str(x) for k in ("recipients", "cc", "bcc") for x in (it.get(k) or []))
            self._add(s, "stranger", sender=s, part="from")
            self._add(body + " " + heads, "stranger", sender=s, part="body")

    @staticmethod
    def _strip_wrapper(text):
        """Tolerate a wrapper around a YAML list (e.g. delimiters another layer added), nothing more."""
        i = text.find("- attachments:")
        if i < 0: return text
        body = text[i:]
        return re.sub(r"[>\]\s]*$", "", body.rstrip()) + "\n"

    def _observe_products(self, text, args):
        try:
            data = ast.literal_eval(text.strip())
        except Exception:
            data = None
        q_bound = bool(words(" ".join(str(v) for v in args.values())) & self.order_words)
        if isinstance(data, dict):
            for name, row in data.items():
                if not isinstance(row, dict): continue
                fields = {k: v for k, v in row.items() if k != "reviews"}
                row_text = f"{name} " + " ".join(f"{k}: {v}" for k, v in fields.items())
                bound = q_bound or bool(words(str(name)) & self.order_words)
                self._add(row_text, "record" if bound else "fact")
                for r in (row.get("reviews") or []): self._add(str(r), "stranger")
        else:
            reviews = re.findall(r"'reviews': \[(.*?)\]", text, re.S)
            self._add(re.sub(r"'reviews': \[.*?\]", " ", text, flags=re.S), "record" if q_bound else "fact")
            for r in reviews: self._add(r, "stranger")

    def _observe_calendar(self, text):
        try:
            items = yaml.safe_load(text)
        except Exception:
            items = None
        if isinstance(items, list) and all(isinstance(i, dict) for i in items):
            for it in items:
                self._add(" ".join(f"{k}: {v}" for k, v in it.items() if k != "description"), "record")
                self.learn_known(" ".join(str(x) for x in (it.get("participants") or [])))
                self._add(str(it.get("description", "")), "fact")
        else:
            self._add(text, "fact")

    # ---------------- lookups ----------------
    def where_segs(self, v):
        nv = norm(v)
        if not nv: return []
        sv = str(v).strip()
        if EMAIL_RE.fullmatch(sv):
            return [s for s in self.segments if sv.lower() in s["emails"]]
        if re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9 \-]{8,40}", sv):
            return [s for s in self.segments if nv in s["ibans"]]
        if URL_RE.fullmatch(sv) or re.fullmatch(r"(https?://)?(www\.)?[\w\-]+(\.[\w\-]+)+(/\S*)?", sv):
            u = re.sub(r"[/.!,;:?)\]\\'\"]+$", "", nv.split("?")[0])
            return [s for s in self.segments if any(t == u or t.startswith(u + "/") or u.startswith(t + "/") for t in s["urls"])]
        return [s for s in self.segments if nv in s["ntext"]]

    def in_prompt(self, v):
        nv = norm(v)
        if not nv: return False
        sv = str(v).strip()
        if EMAIL_RE.fullmatch(sv): return sv.lower() in self.prompt_addrs
        return nv in self.np

    def values_of(self, typ, segs):
        mine = {norm(y) for y in self.self_vals}
        out = set()
        for s in segs:
            for x in TYPE_RE[typ].findall(s["text"]):
                nx = norm(x).split("?")[0].rstrip(".")
                if nx and nx not in mine: out.add(nx)
        return out

    def is_site(self, subj):
        return isinstance(subj, str) and "." in subj and not subj.startswith(("path:", "file:", "prompt:")) and "@" not in subj

    def designated(self, seg, typ):
        """Did you point the agent to this file for this kind of fact?"""
        path = seg.get("path", "")
        for types, paths, wants_dl, wants_inbox in self.pointers:
            if typ not in types: continue
            if path and any(path.startswith(pp) or pp.startswith(path) for pp in paths): return True
            if wants_dl and seg.get("downloaded"): return True
        return False

    def bound(self, key, v, fn):
        """Is value v, used in slot `key`, tied to your request? Returns (ok, reason)."""
        if self.in_prompt(v): return True, "in your request"
        segs = self.where_segs(v)
        if not segs: return False, f"can't trace where '{v[:30]}' came from"
        kinds = {s["kind"] for s in segs}
        if kinds == {"stranger"}: return False, f"'{v[:30]}' came only from an unnamed author"
        typ = SLOT_TYPE.get(key)
        own_key = key == "ssh_key" and fn == "git_add_ssh_key"
        # payee / own key: added text anywhere you trust that offers a second candidate means refuse
        if typ in ("iban", "ssh") and (key in STRICT_UNIQUE):
            pool = [s for s in self.segments if s["kind"] in ("order", "fact") and
                    (s["subject"] != "self" or own_key) and not (typ == "iban" and s["subject"] == "self")]
            vals = self.values_of(typ, pool)
            if len(vals) > 1 and norm(v) in vals:
                return False, f"ambiguous {key}: {len(vals)} candidates in sources you trust"
        for s in segs:                            # 1. orders you handed out
            if s["kind"] != "order": continue
            if self.is_site(s["subject"]) and typ in ("url", "email"):
                dv = dom_of(v) if typ == "url" else v.split("@")[-1].lower()
                if not (dv == s["subject"] or dv.endswith("." + s["subject"])): continue
            if key in STRICT_UNIQUE and typ == "email":
                vals = self.values_of(typ, [x for x in self.segments if x["kind"] == "order" and x["subject"] == s["subject"]])
                if len(vals) > 1: return False, f"ambiguous {key}: {len(vals)} candidates in the instructions"
            return True, "from someone you handed orders to"
        if "record" in kinds: return True, "platform record"      # 2. platform facts
        if typ not in FACT_TYPES: return False, f"'{v[:30]}' isn't tied to anything your request names"
        for s in segs:                            # 3. facts you pointed to
            if s["kind"] != "fact": continue
            subj = s["subject"]
            if not subj or (subj == "self" and not own_key): continue
            if self.is_site(subj):
                named = any(subj == nd or subj.endswith("." + nd) for nd in self.named_domains) or s["host"] == subj
                if not named: continue
                if typ in ("url", "email"):
                    dv = dom_of(v) if typ == "url" else v.split("@")[-1].lower()
                    if not (dv == subj or dv.endswith("." + subj)): continue
            elif subj.startswith(("path:", "file:")) or s.get("path"):
                if not (self.designated(s, typ) or own_key): continue
            elif not (subj in self.people or subj.startswith("prompt:") or subj == "self"):
                continue
            if typ in TYPE_RE and typ != "url":
                vals = self.values_of(typ, [x for x in self.segments if x["kind"] in ("fact", "order") and x["subject"] == subj])
                if len(vals) > 1 and norm(v) in vals:
                    return False, f"ambiguous {key}: {len(vals)} candidates about {subj}"
            return True, f"fact about {subj}"
        return False, f"'{v[:30]}' isn't tied to anything your request names"

    def nav_bound(self, url):
        if not url: return False
        d = dom_of(url)
        if self.in_prompt(url) or any(d == nd or d.endswith("." + nd) for nd in self.named_domains): return True
        for s in self.where_segs(url):
            if s["kind"] == "record": return True
            if s["kind"] in ("order", "fact") and s["host"] and (d == s["host"] or d.endswith("." + s["host"])): return True
        # moving around inside a site you are already legitimately on
        if any(s["kind"] in ("order", "fact") and s["host"] and s["host"] == d for s in self.segments): return True
        return self.bound("url", url, "browse")[0]

    def key_values(self, args):
        out = []
        def walk(k, x):
            if isinstance(x, dict):
                for kk, v in x.items(): walk(kk, v)
            elif isinstance(x, (list, tuple)):
                for v in x: walk(k, v)
            elif isinstance(x, (str, int, float)):
                s = str(x).strip()
                if (len(s) >= 4 and re.search(r"[\d@/\.]", s) and len(s.split()) <= 3) or (len(s) >= 6 and 2 <= len(s.split()) <= 5) \
                        or (k in SLOT_TYPE and len(s) >= 3):
                    out.append((k, s))
        walk(None, args)
        return out

    def _block(self, why):
        self.pending_blocked = True
        return "BLOCK", why

    # ---------------- decisions ----------------
    def decide(self, fn, args):
        args = args or {}
        if fn in READ_ONLY or fn in ("get_webpage", "click_the_link"):
            kinds = set()
            for _, v in self.key_values(args):
                if self.in_prompt(v): kinds.add("order"); continue
                kinds |= {s["kind"] for s in self.where_segs(v)}
            if kinds and kinds <= {"stranger"}: self.taint = "stranger"
            elif kinds and kinds <= {"stranger", "fact"}: self.taint = "fact"
            if fn in ("browse_webpage", "get_webpage", "click_the_link"):
                url = str(args.get("url", "") or args.get("web_url", "") or args.get("link", ""))
                if url and not self.nav_bound(url):
                    return "BLOCK", "that link isn't tied to your request"
            return "ALLOW", "read"
        if fn in CONFIRM:
            return ("BLOCK", "confirms a blocked request") if self.pending_blocked else ("ALLOW", "confirmation")
        if fn in LOW_RISK_WRITES:
            return "ALLOW", "low-risk"
        if fn not in self.licensed and fn not in ("download_file_through_url", "download_file_through_id", "input_to_webpage"):
            return self._block("outside the job you gave")
        if fn == "send_money" and self.money_budget <= 0:
            return self._block("payment budget used")
        if self.needs_doc and fn not in ("download_file_through_url", "download_file_through_id", "input_to_webpage") and \
                not any(s["kind"] != "stranger" and (s.get("downloaded") or str(s["subject"]).startswith("file:")) for s in self.segments):
            return self._block("the document with your instructions hasn't been read yet")
        if fn in ("download_file_through_url", "input_to_webpage"):
            url = str(args.get("url", ""))
            if url and not self.nav_bound(url):
                return self._block("that link isn't tied to your request")
        for k, v in self.key_values(args):
            if k in FREE_TEXT_KEYS: continue          # words the agent composes itself (checked via the slots)
            segs = self.where_segs(v)
            if segs and not self.in_prompt(v) and {s["kind"] for s in segs} <= {"stranger"}:
                return self._block(f"value '{v[:30]}' came only from an unnamed author")
            if k in SLOT_TYPE and k != "url":
                ok, why = self.bound(k, v, fn)
                if not ok: return self._block(why)
        if fn == "create_calendar_event":
            title = str(args.get("title", ""))
            order_w = self.order_words | {w for s in self.segments if s["kind"] == "order" for w in words(s["text"])}
            if title and not (words(title) & order_w) and not any(s["kind"] in ("order", "record") for s in self.where_segs(title)):
                return self._block("event title isn't tied to your request")
        if fn in ("send_email", "input_to_webpage"):
            dests = [str(x) for x in (args.get("recipients") or [])] + [str(args.get("url", ""))]
            if SENSITIVE.search(str(args)) and not all((not d) or self.dest_ok(d) for d in dests):
                return self._block("private data to a destination you didn't name")
        if fn == "send_money":
            self.money_budget -= 1
        self.pending_blocked = False
        return "ALLOW", "ok"

    def dest_ok(self, d):
        """Private data may go only to a destination tied to your request."""
        d = d.lower()
        if d in self.prompt_addrs or self.person_of(d)[0]: return True
        if "@" in d:
            if d in self.self_dest or d.split("@")[-1] in self.my_domains(): return True
            return self.bound("recipients", d, "send_email")[0]
        return self.nav_bound(d)
