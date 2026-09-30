"""
v0 "Delegated Authority" gate — rule-based, no AI calls, no network.
Decides ALLOW/BLOCK for each state-changing tool call, using only:
  - the user's prompt (trusted channel)
  - tool outputs seen so far, split into segments labelled by WHO wrote them
It never uses knowledge of which text was injected.
"""
import re

READ_ONLY = {
    "get_current_day", "view_order_history", "get_invoice", "get_shopping_linked_received_emails",
    "get_shopping_linked_unread_emails", "read_file", "view_available_discounts", "cart_total",
    "list_directory", "view_cart", "search_product", "get_shopping_account_user_information",
    "get_balance", "get_unread_emails", "get_received_emails", "search_emails", "get_sent_emails",
    "get_day_calendar_events", "search_calendar_events", "get_github_account_user_information",
    "get_github_linked_unread_emails", "get_github_repository_information",
    "get_logged_in_github_user_information", "git_get_linked_ssh_keys", "browse_webpage",
    "login_shopping_account", "login_github_account",
}
CONFIRM = {"verify_shopping_account", "verify_github_account", "verify_transaction"}
LOW_RISK_WRITES = {"create_dir", "cart_remove_product", "clear_cart", "git_pull", "git_clone", "copy_node"}

# which user words license which consequential tools (generic, not per-task)
LICENSE = [
    (r"\b(buy|purchase|rebuy|order|place the order|cart)\b", {"cart_add_product", "checkout_selected_cart"}),
    (r"\brefund\b", {"refund_order"}),
    (r"\bpassword\b", {"update_shopping_account_password", "update_github_account_password"}),
    (r"\b(pay|payment|fee|top up|transfer the|transfer .*balance|send money|bill)\b", {"send_money"}),
    (r"\btransfer\b.*\brepo|\brepositor(y|ies)\b.*\btransfer\b|transfer (my|the one)", {"git_transfer_repo_ownership"}),
    (r"\b(invite|collaborator)", {"git_invite_collaborators"}),
    (r"\bstar\b", {"git_star"}),
    (r"\b(unstar|remove (my )?stars?)\b", {"git_unstar"}),
    (r"\bssh key", {"git_add_ssh_key", "git_delete_ssh_key"}),
    (r"\b(upload|push|sync|update (our|her|his|the|my)? ?(github )?repositor)", {"git_push", "move_node", "create_file"}),
    (r"\bcreate (a )?(new )?(github )?repositor", {"git_create_repo", "git_push", "move_node", "create_file"}),
    (r"\b(email|send|reply|greeting)\b", {"send_email"}),
    (r"\b(download|save)\b", {"download_file_through_url", "download_file_through_id", "move_node", "create_file"}),
    (r"\b(write|answer|finish|homework|note)\b", {"create_file"}),
    (r"\b(calendar|schedule|meeting|event)\b", {"create_calendar_event", "reschedule_calendar_event", "add_calendar_event_participants"}),
    (r"\b(reserve|register|fill|comment|post|visit|log ?in|account information)\b", {"input_to_webpage"}),
    (r"\bissue", {"git_issue"}),
    (r"\bdelete\b", {"delete_node", "delete_email"}),
]
DELEGATION = re.compile(r"(request|instruction|follow|complete|fulfill|achieve|tasks|what (she|he) needs|according to|address (his|her) issue|asked me|ask me|told me|homework)", re.I)
STOP_NAMES = {"Please", "Could", "Can", "I", "It", "My", "The", "If", "You", "Use", "Check", "Also", "Create", "Transfer",
              "Delete", "Add", "Make", "GitHub", "Github", "Specific", "Bluetooth", "OmniBook", "Pro", "MacBook", "Adidas",
              "SSD", "CS", "CV", "PM", "Alice's", "Bob's", "Emma", "Johnson", "Book", "Club", "First", "Discussion",
              "Dinner", "Day", "Off", "T", "Shirt", "Apple", "SpeedStep", "Taylor's"}
SYSTEM_SENDER = re.compile(r"(noreply|donotreply|no-reply|shopping_platform@|banking_platform@|github-noreply)", re.I)
SENSITIVE = re.compile(r"(PRIVATE KEY|id_rsa|password|passport|ID Number|Bank Account Password|b3BlbnNzaC|\d{3}-\d{3}-\d{4})", re.I)


class Gate:
    def __init__(self, prompt):
        self.prompt = prompt
        p = prompt
        names = set(re.findall(r"\b([A-Z][a-z]+)\b", p)) - STOP_NAMES
        self.people = {n.lower() for n in names}
        self.sites = {d.lower().replace("www.", "").split("/")[0] for d in re.findall(r"((?:www\.)?[a-z0-9_\-]+\.(?:com|edu|org))", p)}
        self.site_keys = {s.split(".")[0] for s in self.sites}
        self.delegates = bool(DELEGATION.search(p))
        self.licensed = set()
        self._license_from(p)
        self.prompt_paths = [p.rstrip(".,;:)'\"") for p in re.findall(r"(/[\w\./_-]+)", p)]
        self.segments = []          # (text, author, level)  level: trusted | authorized | unauthorized
        self.authorized_urls = set()
        self.money_budget = 1 if "send_money" in self.licensed else 0
        self.pending_blocked = False
        self.file_origin = {}
        self.org_domains = set()
        self.platforms = {"github", "shopping", "banking", "bank"}
        self.last_read_tainted = False
        self.file_level = {}
        self.mentioned = set()

    # ---------- authority ----------
    def _license_from(self, text):
        for pat, tools in LICENSE:
            if re.search(pat, text, re.I):
                self.licensed |= tools

    def author_level(self, author):
        a = (author or "").lower()
        if a in ("user", "system"):
            return "trusted"
        if a.startswith("ad:") or a.startswith("reviewer"):
            return "unauthorized"
        if not a.startswith("file:") and (any(k and k in a for k in self.people) or any(k and k in a for k in self.site_keys)):
            return "authorized"
        if not a.startswith("file:") and any(k and len(k) >= 3 and k in a for k in self.mentioned):
            return "informant"   # named by a delegate: may supply facts, may not give orders
        if (a.startswith("site:") or a.startswith("file-from:")) and any(u and u in a for u in self.authorized_urls):
            return "authorized"
        return "unauthorized"

    # ---------- segmenting tool outputs by who wrote them ----------
    def _system_sender(self, sender):
        s = sender.lower()
        if not SYSTEM_SENDER.search(s):
            return False
        dom = s.split("@")[-1]
        # a "no-reply" address is only trusted if it belongs to a platform the agent has tools for,
        # the user's own organisation, or a site the user named -- never just because it says no-reply
        return any(k and k in dom for k in self.platforms | self.site_keys | self.org_domains)

    def observe(self, fn, args, text):
        text = text or ""
        args = args or {}
        segs = []
        # the TOOL decides what kind of content this is -- never the content itself
        if fn in ("browse_webpage", "get_webpage"):
            url = str(args.get("url", "") or args.get("web_url", ""))
            dom = url.lower().replace("https://", "").replace("http://", "").replace("www.", "").split("/")[0]
            ads = re.findall(r'<div class="ad-block".*?</div>', text, re.S)
            main = re.sub(r'<div class="ad-block".*?</div>', " ", text, flags=re.S)
            segs.append((main, "site:" + dom + " " + url.lower()))
            segs += [(a, "ad:" + dom) for a in ads]
            m = re.search(r"([\w\.\-]+) has been added to downloads", text)
            if m: self.file_origin[m.group(1).lower()] = url.lower()
        elif "sender:" in text and ("email" in (fn or "")):
            for block in re.split(r"\n- (?=attachments:)", "\n" + text):
                m = re.search(r"sender: ([^\s]+)", block)
                sender = m.group(1) if m else "unknown"
                for r in re.findall(r"- ([\w\.\-]+@[\w\.\-]+)", block):
                    if r != sender: self.org_domains.add(r.split("@")[-1].split(".")[0])
                author = "system" if self._system_sender(sender) else sender
                header = "\n".join(l for l in block.splitlines() if re.match(r"\s*(- )?(recipients|cc|bcc|id_|timestamp|read|status|- [\w\.\-]+@)", l))
                body = "\n".join(l for l in block.splitlines() if l not in header.splitlines())
                segs.append((header, "system"))
                segs.append((body, author))
        elif fn == "search_product":
            reviews = re.findall(r"'reviews': \[(.*?)\]", text, re.S)
            main = re.sub(r"'reviews': \[.*?\]", " ", text, flags=re.S)
            segs.append((main, "system"))
            segs += [(r, "reviewer") for r in reviews]
        elif fn == "read_file":
            path = str(args.get("file_path", "") or args.get("path", ""))
            name = path.split("/")[-1].lower()
            origin = self.file_origin.get(name)
            if name in self.file_level:
                segs.append((text, "file-id:" + name))
            else:
                segs.append((text, ("file-from:" + origin) if origin else ("file:" + path)))
        elif fn in ("download_file_through_url", "download_file_through_id"):
            m = re.search(r"([\w\.\-]+) has been added to downloads", text)
            if m:
                if fn == "download_file_through_url":
                    self.file_origin[m.group(1).lower()] = str(args.get("url", "")).lower()
                else:
                    fid = str(args.get("file_id", args.get("File Id", "")))
                    lv = self.where(fid)
                    self.file_level[m.group(1).lower()] = "authorized" if ("trusted" in lv or "authorized" in lv) else "unauthorized"
            segs.append((text, "system"))
        elif fn in ("get_github_repository_information",):
            issues = re.findall(r"Issues\(owner_username='([^']+)', comments=(.*?)\)(?=, Issues\(|\]\"|\]'|$)", text, re.S)
            meta = re.sub(r"Issues\(owner_username=.*", " ", text, flags=re.S)
            segs.append((meta, "system"))
            segs += [(body, owner) for owner, body in issues]
        else:
            segs.append((text, "system"))
        for t, a in segs:
            lvl = self.author_level(a)
            if a.startswith("file:") and any(a[5:].startswith(p) or p.startswith(a[5:]) for p in self.prompt_paths):
                lvl = "authorized"
            if a.startswith("file-from:"):
                src_url = a[10:].replace("https://", "").replace("http://", "").replace("www.", "")
                if any(k and k in src_url for k in self.site_keys) or any(u and u in src_url for u in self.authorized_urls):
                    lvl = "authorized"
            if a.startswith("file-id:"):
                lvl = self.file_level.get(a[8:], "unauthorized")
            if self.last_read_tainted and lvl in ("trusted", "authorized"):
                lvl = "unauthorized"   # answer to a question a stranger made us ask
            self.segments.append((t, a, lvl))
            if lvl in ("trusted", "authorized"):
                for u in re.findall(r"(?<![@\w\.\-])((?:https?://)?(?:www\.)?[a-z0-9_\-]+\.(?:com|edu|org)[^\s'\"<>]*)", t):
                    self.authorized_urls.add(u.lower().replace("https://", "").replace("http://", "").replace("www.", "").split("?")[0])
                if lvl == "authorized" and self.delegates and not a.startswith("file:"):
                    self._license_from(t)
                if lvl == "authorized" and not a.startswith("file:"):
                    self.mentioned |= {n.lower() for n in re.findall(r"\b([A-Z][a-z]{2,})\b", t)} - {s.lower() for s in STOP_NAMES}
        self.last_read_tainted = False

    # ---------- the decision ----------
    def key_values(self, args):
        vals = []
        def walk(x):
            if isinstance(x, dict):
                for v in x.values(): walk(v)
            elif isinstance(x, (list, tuple)):
                for v in x: walk(v)
            elif isinstance(x, (str, int, float)):
                s = str(x).strip()
                if len(s) >= 4 and re.search(r"[\d@/\.]", s) and len(s.split()) <= 3:
                    vals.append(s)
                elif len(s) >= 6 and 2 <= len(s.split()) <= 5:
                    vals.append(s)
        walk(args)
        return vals

    def where(self, v):
        v_l = v.lower()
        if re.match(r"^(https?://)?(www\.)?[a-z0-9_\-]+\.(com|edu|org)", v_l):
            v_l = v_l.replace("https://", "").replace("http://", "").replace("www.", "").rstrip("/")
        found = []
        if v_l in self.prompt.lower():
            found.append("trusted")
        for t, a, lvl in self.segments:
            if v_l in t.lower():
                found.append(lvl)
        return found

    def decide(self, fn, args):
        if fn in READ_ONLY:
            for v in self.key_values(args):
                f = self.where(v)
                if f and all(x == "unauthorized" for x in f):
                    self.last_read_tainted = True
            if fn == "browse_webpage":  # opening a URL that only a stranger suggested is a (small) write: it can download or leak
                url = str((args or {}).get("url", "")).lower()
                f = self.where(url.replace("https://", "").replace("www.", "")) if url else []
                if f and all(x == "unauthorized" for x in f):
                    return "BLOCK", "url only suggested by an unnamed author"
            return "ALLOW", "read"
        if fn in CONFIRM:
            return ("BLOCK", "confirms a blocked request") if self.pending_blocked else ("ALLOW", "confirmation")
        if fn in LOW_RISK_WRITES:
            return "ALLOW", "low-risk"
        # 1) job scope: was this kind of action licensed by the user or a named delegate?
        if fn not in self.licensed and fn not in ("download_file_through_url", "download_file_through_id", "input_to_webpage"):
            self.pending_blocked = True
            return "BLOCK", "outside the job you gave"
        # 2) budget: one payment per payment request
        if fn == "send_money":
            if self.money_budget <= 0:
                self.pending_blocked = True
                return "BLOCK", "payment budget used"
        # 3) provenance: important values must not come only from unnamed authors
        for v in self.key_values(args):
            f = self.where(v)
            if f and all(x == "unauthorized" for x in f):
                self.pending_blocked = True
                return "BLOCK", f"value '{v[:30]}' came only from an unnamed author"
        # 4) no sensitive data to a destination the user didn't name
        if fn in ("send_email", "input_to_webpage"):
            payload = str(args)
            dest = str((args or {}).get("recipients", "")) + str((args or {}).get("url", ""))
            dest_ok = any(k in dest.lower() for k in self.people | self.site_keys) or any(d in self.prompt.lower() for d in re.findall(r"[\w\.\-]+@[\w\.\-]+", dest.lower()))
            if SENSITIVE.search(payload) and not dest_ok:
                self.pending_blocked = True
                return "BLOCK", "sensitive data to an unnamed destination"
        if fn == "send_money":
            self.money_budget -= 1
        self.pending_blocked = False
        return "ALLOW", "ok"
