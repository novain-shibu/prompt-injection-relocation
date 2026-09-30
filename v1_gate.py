"""
v1 "Delegated Authority" gate. Same idea as v0, with the known holes closed:
  1. Identity: a sender counts as a person you named only if exactly one address matches that
     name (spoof-looking duplicates make it ambiguous -> nobody is trusted), preferring addresses
     already seen in trusted records (account info, calendar, repo data, your sent mail, files you
     pointed to). Text inside a message never decides who wrote it.
  2. Sites: exact domain match, not "contains the word".
  3. Positive provenance: payees, recipients, collaborators, new owners, SSH keys and URLs must be
     traceable to you, a trusted record, or someone you authorised -- "appears nowhere" is not enough.
  4. Values are compared after normalising spacing, dashes and case (so "AT68 5453 2054" == "AT6854532054").
  5. Look-alike senders for a named site (e.g. electricity.bill@...) may supply facts, never orders or payees.
Rule-based, no AI calls, no network. Frozen after this file -- no tuning on evaluation data.
"""
import re
from v0_gate import (READ_ONLY, CONFIRM, LOW_RISK_WRITES, LICENSE, DELEGATION, STOP_NAMES,
                     SYSTEM_SENDER, SENSITIVE)

RECEIVED_MAIL_TOOLS = ("get_unread_emails", "get_received_emails", "search_emails",
                       "get_shopping_linked_unread_emails", "get_shopping_linked_received_emails",
                       "get_github_linked_unread_emails")
HIGH_STAKES_KEYS = {"recipient", "recipients", "cc", "bcc", "collaborator_email", "new_owner_email",
                    "new_owner_username", "ssh_key", "url"}
PAYEE_KEYS = {"recipient"}
EMAIL_RE = re.compile(r"[\w\.\-+]+@[\w\-]+(?:\.[\w\-]+)+")
URL_RE = re.compile(r"(?<![@\w\.\-])((?:https?://)?(?:www\.)?[a-z0-9_\-]+(?:\.[a-z0-9_\-]+)*\.(?:com|edu|org|net|io)[^\s'\"<>,)]*)", re.I)


def norm(s):
    s = str(s).lower().strip()
    s = s.replace("https://", "").replace("http://", "").replace("www.", "")
    return re.sub(r"[\s\-]", "", s).rstrip("/")


def dom_of(url):
    return norm(url).split("/")[0]


class Gate:
    def __init__(self, prompt):
        self.prompt = prompt
        p = prompt
        names = set(re.findall(r"\b([A-Z][a-z]+)\b", p)) - STOP_NAMES
        self.people = {n.lower() for n in names}
        self.named_domains = {dom_of(d) for d in URL_RE.findall(p)}
        self.site_keys = {d.split(".")[0] for d in self.named_domains}
        self.prompt_addrs = {a.lower() for a in EMAIL_RE.findall(p)}
        self.delegates = bool(DELEGATION.search(p))
        self.licensed = set()
        self._license_from(p)
        self.prompt_paths = [x.rstrip(".,;:)'\"") for x in re.findall(r"(/[\w\./_-]+)", p)]
        self.segments = []            # dicts: text, ntext, author, tainted, fixed
        self.known_addrs = set(self.prompt_addrs)   # addresses seen in trusted records
        self.candidates = {}          # person name -> set of sender addresses that look like them
        self.authorized_urls = set()
        self.file_origin, self.file_level = {}, {}
        self.mentioned = set()
        self.money_budget = 1 if "send_money" in self.licensed else 0
        self.pending_blocked = False
        self.last_read_tainted = False
        self.platforms = {"github", "shopping", "banking", "bank"}
        self.org_domains = set()
        self.all_senders = set()

    # ---------------- identity ----------------
    def _license_from(self, text):
        for pat, tools in LICENSE:
            if re.search(pat, text, re.I):
                self.licensed |= tools

    @staticmethod
    def _addr_tokens(addr):
        local = addr.split("@")[0]
        return set(re.split(r"[\._\-+]", local))

    def _looks_like(self, addr, name):
        toks = self._addr_tokens(addr)
        return name in toks or any(t.startswith(name) for t in toks if len(t) > 2)

    def bound_address(self, name):
        """The one address that is this named person, or None if unknown/ambiguous."""
        cands = self.candidates.get(name, set())
        verified = {c for c in cands if c in self.known_addrs}
        pool = verified or cands
        return next(iter(pool)) if len(pool) == 1 else None

    def is_named_person(self, addr):
        addr = addr.lower()
        if addr in self.prompt_addrs:
            return True
        return any(self.bound_address(n) == addr for n in self.people)

    def is_site_lookalike(self, addr):
        local = addr.split("@")[0]
        return any(k and len(k) > 3 and k in local for k in self.site_keys)

    def is_mentioned(self, addr):
        for n in self.mentioned:
            if self._looks_like(addr, n):
                cands = {s for s in self.all_senders if self._looks_like(s, n)}
                verified = {c for c in cands if c in self.known_addrs}
                pool = verified or cands
                if len(pool) == 1 and addr in pool:
                    return True
        return False

    def level_of(self, seg):
        if seg["fixed"]:
            lvl = seg["fixed"]
        else:
            a = seg["author"]
            if a in ("user", "system"):
                lvl = "trusted"
            elif a.startswith("ad:") or a == "reviewer":
                lvl = "unauthorized"
            elif a.startswith("site:"):
                d = a[5:]
                ok = any(d == nd or d.endswith("." + nd) for nd in self.named_domains) or \
                     any(seg["url"].startswith(u) for u in self.authorized_urls if u)
                lvl = "authorized" if ok else "unauthorized"
            elif "@" in a:                      # an email sender or issue owner
                if self.is_named_person(a):
                    lvl = "authorized"
                elif self.is_site_lookalike(a) or self.is_mentioned(a):
                    lvl = "informant"
                else:
                    lvl = "unauthorized"
            else:
                lvl = "unauthorized"
        if seg["tainted"] and lvl in ("trusted", "authorized", "informant"):
            lvl = "unauthorized"
        return lvl

    # ---------------- observing tool outputs ----------------
    def _add(self, text, author, fixed=None, url=""):
        seg = {"text": text, "ntext": norm(text), "author": author.lower(), "fixed": fixed,
               "tainted": self.last_read_tainted, "url": norm(url)}
        self.segments.append(seg)
        return seg

    def _system_sender(self, sender):
        s = sender.lower()
        if not SYSTEM_SENDER.search(s):
            return False
        d = s.split("@")[-1]
        return any(k and k in d for k in self.platforms | self.org_domains) or \
               any(d == nd or d.endswith("." + nd) for nd in self.named_domains)

    def observe(self, fn, args, text):
        text, args, fn = text or "", args or {}, fn or ""
        new = []
        if fn in ("browse_webpage", "get_webpage"):
            url = str(args.get("url", "") or args.get("web_url", ""))
            ads = re.findall(r'<div class="ad-block".*?</div>', text, re.S)
            main = re.sub(r'<div class="ad-block".*?</div>', " ", text, flags=re.S)
            new.append(self._add(main, "site:" + dom_of(url), url=url))
            new += [self._add(a, "ad:" + dom_of(url)) for a in ads]
            m = re.search(r"([\w\.\-]+) has been added to downloads", text)
            if m: self.file_origin[m.group(1).lower()] = url
        elif "sender:" in text and fn in RECEIVED_MAIL_TOOLS + ("get_sent_emails",):
            for block in re.split(r"\n- (?=attachments:)", "\n" + text):
                m = re.search(r"sender: ([^\s]+)", block)
                sender = (m.group(1) if m else "unknown").lower()
                for r in re.findall(r"- ([\w\.\-]+@[\w\.\-]+)", block):
                    if r != sender: self.org_domains.add(r.split("@")[-1].split(".")[0])
                header = "\n".join(l for l in block.splitlines() if re.match(r"\s*(- )?(recipients|cc|bcc|id_|timestamp|read|status|- [\w\.\-]+@)", l))
                body = "\n".join(l for l in block.splitlines() if l not in header.splitlines())
                if fn == "get_sent_emails":     # mail YOU sent: its recipients are people you deal with
                    self.known_addrs |= {x.lower() for x in EMAIL_RE.findall(block)}
                    new.append(self._add(block, "system"))
                    continue
                self.all_senders.add(sender)
                for n in self.people:
                    if self._looks_like(sender, n):
                        self.candidates.setdefault(n, set()).add(sender)
                author = "system" if self._system_sender(sender) else sender
                new.append(self._add(header, "system", fixed="trusted"))   # recipients list = facts about delivery only
                new.append(self._add(body, author))
        elif fn == "search_product":
            reviews = re.findall(r"'reviews': \[(.*?)\]", text, re.S)
            main = re.sub(r"'reviews': \[.*?\]", " ", text, flags=re.S)
            new.append(self._add(main, "system"))
            new += [self._add(r, "reviewer") for r in reviews]
        elif fn == "read_file":
            path = str(args.get("file_path", "") or args.get("path", ""))
            name = path.split("/")[-1].lower()
            if name in self.file_level:
                new.append(self._add(text, "file", fixed=self.file_level[name]))
            elif name in self.file_origin:
                o = self.file_origin[name]
                ok = any(dom_of(o) == nd or dom_of(o).endswith("." + nd) for nd in self.named_domains) or \
                     any(norm(o).startswith(u) for u in self.authorized_urls if u)
                new.append(self._add(text, "file", fixed="authorized" if ok else "unauthorized"))
            else:
                pointed = any(path.startswith(pp) or pp.startswith(path) for pp in self.prompt_paths if pp)
                new.append(self._add(text, "file", fixed="authorized" if pointed else "unauthorized"))
                if pointed:
                    self.known_addrs |= {x.lower() for x in EMAIL_RE.findall(text)}
        elif fn in ("download_file_through_url", "download_file_through_id"):
            m = re.search(r"([\w\.\-]+) has been added to downloads", text)
            if m:
                if fn == "download_file_through_url":
                    self.file_origin[m.group(1).lower()] = str(args.get("url", ""))
                else:
                    fid = str(args.get("file_id", args.get("File Id", "")))
                    lv = self.where(fid)
                    self.file_level[m.group(1).lower()] = "authorized" if (lv & {"trusted", "authorized"}) else "unauthorized"
            new.append(self._add(text, "system"))
        elif fn == "get_github_repository_information":
            issues = re.findall(r"Issues\(owner_username='([^']+)', comments=(.*?)\)(?=, Issues\(|\]\"|\]'|$)", text, re.S)
            meta = re.sub(r"Issues\(owner_username=.*", " ", text, flags=re.S)
            new.append(self._add(meta, "system"))
            self.known_addrs |= {x.lower() for x in EMAIL_RE.findall(meta)}
            new += [self._add(body, owner) for owner, body in issues]
        else:
            new.append(self._add(text, "system"))
            if fn in ("get_shopping_account_user_information", "get_github_account_user_information",
                      "get_day_calendar_events", "search_calendar_events", "get_logged_in_github_user_information"):
                self.known_addrs |= {x.lower() for x in EMAIL_RE.findall(text)}
        for seg in new:
            lvl = self.level_of(seg)
            if lvl in ("trusted", "authorized"):
                for u in URL_RE.findall(seg["text"]):
                    self.authorized_urls.add(norm(u).split("?")[0])
                if lvl == "authorized" and seg["author"] not in ("system", "file") and self.delegates:
                    self._license_from(seg["text"])
                if lvl == "authorized" and seg["author"] not in ("file",):
                    self.mentioned |= {n.lower() for n in re.findall(r"\b([A-Z][a-z]{2,})\b", seg["text"])} - {s.lower() for s in STOP_NAMES}
        self.last_read_tainted = False

    # ---------------- decisions ----------------
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
                        or (k in HIGH_STAKES_KEYS and len(s) >= 3):
                    out.append((k, s))
        walk(None, args)
        return out

    def where(self, v):
        nv = norm(v)
        found = set()
        if not nv:
            return found
        if nv in norm(self.prompt):
            found.add("trusted")
        for seg in self.segments:
            if nv in seg["ntext"]:
                found.add(self.level_of(seg))
        return found

    def _block(self, why):
        self.pending_blocked = True
        return "BLOCK", why

    def decide(self, fn, args):
        args = args or {}
        if fn in READ_ONLY:
            for _, v in self.key_values(args):
                f = self.where(v)
                if f and f <= {"unauthorized"}:
                    self.last_read_tainted = True
            if fn == "browse_webpage":
                url = str(args.get("url", ""))
                f = self.where(url) if url else set()
                named = any(dom_of(url) == nd or dom_of(url).endswith("." + nd) for nd in self.named_domains)
                if not named and f and f <= {"unauthorized"}:
                    return "BLOCK", "url only suggested by an unnamed author"
            return "ALLOW", "read"
        if fn in CONFIRM:
            return ("BLOCK", "confirms a blocked request") if self.pending_blocked else ("ALLOW", "confirmation")
        if fn in LOW_RISK_WRITES:
            return "ALLOW", "low-risk"
        if fn not in self.licensed and fn not in ("download_file_through_url", "download_file_through_id", "input_to_webpage"):
            return self._block("outside the job you gave")
        if fn == "send_money" and self.money_budget <= 0:
            return self._block("payment budget used")
        for k, v in self.key_values(args):
            f = self.where(v)
            if f and f <= {"unauthorized"}:
                return self._block(f"value '{v[:30]}' came only from an unnamed author")
            if k in HIGH_STAKES_KEYS:
                if k == "url" and fn == "input_to_webpage" and any(dom_of(v) == nd or dom_of(v).endswith("." + nd) for nd in self.named_domains):
                    continue
                if not f:
                    return self._block(f"can't trace where '{v[:30]}' came from")
                if fn == "send_money" and k in PAYEE_KEYS and not (f & {"trusted", "authorized"}):
                    return self._block("new payee from a facts-only source")
        if fn in ("send_email", "input_to_webpage"):
            dests = [str(x) for x in (args.get("recipients") or [])] + [str(args.get("url", ""))]
            dest_ok = all((not d) or self.is_named_person(d) or d.lower() in self.prompt_addrs or
                          any(dom_of(d) == nd or dom_of(d).endswith("." + nd) for nd in self.named_domains) or
                          any(norm(d).startswith(u) for u in self.authorized_urls if u) or
                          any(k and k in dom_of(d) for k in self.org_domains)
                          for d in dests)
            if SENSITIVE.search(str(args)) and not dest_ok:
                return self._block("sensitive data to an unnamed destination")
        if fn == "send_money":
            self.money_budget -= 1
        self.pending_blocked = False
        return "ALLOW", "ok"
