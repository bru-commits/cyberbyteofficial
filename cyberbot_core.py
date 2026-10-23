"""Discord-independent logic for CyberBot.

Config helpers, the SQLite case store, the scammer blacklist file, text helpers
and the punishment runner live here. Nothing in this module imports discord, so
it can be unit-tested without a bot or a network connection.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import tempfile
import time
from contextlib import closing
from dataclasses import dataclass
from typing import Iterable, Optional

# ------------------------------------------------------------------------------
# Configuration / constants
# ------------------------------------------------------------------------------
DB_PATH = os.getenv("CYBERBOT_DB", "cyberbot.db")
SCAMMER_FILE = os.getenv("SCAMMER_FILE", "scammers.json")
COMMUNITY_NAME = os.getenv("COMMUNITY_NAME", "CyberByte")

REPORT_LIMIT_PER_HOUR = 5
THREAD_ARCHIVE_MINUTES = 10080  # 7 days

STATUS_OPEN = "open"
STATUS_NEEDS_INFO = "needs_info"
STATUS_CLOSED = "closed"
OPEN_STATUSES = (STATUS_OPEN, STATUS_NEEDS_INFO)

# Case decisions are stored as short strings:
#   "dismissed", "action: dm_warning, ban", "overturned"
DECISION_DISMISSED = "dismissed"
DECISION_OVERTURNED = "overturned"
DECISION_ACTION_PREFIX = "action:"

CASE_SCAM = "scam"
CASE_BULLYING = "cyberbullying"
CASE_OTHER = "other"
DEFAULT_CASE_TYPE = CASE_SCAM
CASE_TYPE_LABELS = {
    CASE_SCAM: "Scam / fraud",
    CASE_BULLYING: "Cyberbullying / harassment",
    CASE_OTHER: "Other",
}

ACTION_DM = "dm_warning"
ACTION_PUBLIC = "public_warning"
ACTION_BLACKLIST = "blacklist"
ACTION_BAN = "ban"
ACTION_UNBAN = "unban"
ACTION_UNBLACKLIST = "unblacklist"
# DM first (a ban can remove the shared server the DM needs), ban last.
ACTION_ORDER = (ACTION_DM, ACTION_PUBLIC, ACTION_BLACKLIST, ACTION_BAN)
ACTION_LABELS = {
    ACTION_DM: "DM warning",
    ACTION_PUBLIC: "Public warning",
    ACTION_BLACKLIST: "Blacklist",
    ACTION_BAN: "Ban",
    ACTION_UNBAN: "Unban",
    ACTION_UNBLACKLIST: "Remove from blacklist",
}
_LABEL_TO_ACTION = {label.lower(): key for key, label in ACTION_LABELS.items()}

APPEAL_OPEN = "open"
APPEAL_UPHELD = "upheld"
APPEAL_OVERTURNED = "overturned"

HONEYPOT_KICK = "kick"
HONEYPOT_BAN = "ban"
HONEYPOT_TIMEOUT = "timeout"
HONEYPOT_DELETE = "delete"
DEFAULT_HONEYPOT_ACTION = HONEYPOT_KICK
DEFAULT_HONEYPOT_NAME = "security-honeypot"
HONEYPOT_TIMEOUT_HOURS = 24
HONEYPOT_ACTIONS = {
    HONEYPOT_KICK: "Kick",
    HONEYPOT_BAN: "Ban",
    HONEYPOT_TIMEOUT: f"Timeout ({HONEYPOT_TIMEOUT_HOURS} hours)",
    HONEYPOT_DELETE: "Delete message only",
}
HONEYPOT_PHRASES = {
    HONEYPOT_KICK: "kicked",
    HONEYPOT_BAN: "banned",
    HONEYPOT_TIMEOUT: f"timed out for {HONEYPOT_TIMEOUT_HOURS} hours",
    HONEYPOT_DELETE: "deleted, with no other action taken",
}


def env_int(name: str, default: Optional[int] = None) -> Optional[int]:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip())
    except ValueError:
        return default


def case_type_label(case_type: Optional[str]) -> str:
    return CASE_TYPE_LABELS.get(case_type or "", CASE_TYPE_LABELS[CASE_OTHER])


# ------------------------------------------------------------------------------
# Database
# ------------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at INTEGER NOT NULL,
    reporter_id INTEGER NOT NULL,
    suspect_id INTEGER NOT NULL,
    suspect_name TEXT,
    source_guild_id INTEGER,
    source_channel_id INTEGER,
    anchor_message_id INTEGER,
    anchor_sent_at INTEGER,
    anchor_content TEXT,
    verified INTEGER NOT NULL DEFAULT 0,
    details TEXT NOT NULL DEFAULT '',
    pasted_context TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open',
    decision TEXT,
    decision_reason TEXT,
    decided_by INTEGER,
    decided_at INTEGER,
    thread_id INTEGER,
    starter_message_id INTEGER,
    panel_message_id INTEGER,
    reporter_dm_ok INTEGER,
    case_type TEXT NOT NULL DEFAULT 'scam'
);
CREATE INDEX IF NOT EXISTS idx_cases_suspect ON cases(suspect_id);
CREATE INDEX IF NOT EXISTS idx_cases_reporter ON cases(reporter_id, status);
CREATE TABLE IF NOT EXISTS case_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    ts INTEGER NOT NULL,
    actor_id INTEGER,
    kind TEXT NOT NULL,
    text TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_case ON case_events(case_id);
CREATE TABLE IF NOT EXISTS appeals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    appellant_id INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    reason TEXT NOT NULL,
    original_decision TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    decision_reason TEXT,
    decided_by INTEGER,
    decided_at INTEGER,
    thread_id INTEGER,
    starter_message_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_appeals_case ON appeals(case_id);
CREATE TABLE IF NOT EXISTS guild_settings (
    guild_id INTEGER PRIMARY KEY,
    honeypot_channel_id INTEGER,
    honeypot_action TEXT NOT NULL DEFAULT 'kick',
    honeypot_notice_message_id INTEGER
);
CREATE TABLE IF NOT EXISTS autoban_guilds (
    guild_id INTEGER PRIMARY KEY,
    enabled_by INTEGER,
    enabled_at INTEGER NOT NULL
);
"""

CASE_COLUMNS = {
    "created_at", "reporter_id", "suspect_id", "suspect_name", "source_guild_id",
    "source_channel_id", "anchor_message_id", "anchor_sent_at", "anchor_content",
    "verified", "details", "pasted_context", "status", "decision", "decision_reason",
    "decided_by", "decided_at", "thread_id", "starter_message_id", "panel_message_id",
    "reporter_dm_ok", "case_type",
}
APPEAL_COLUMNS = {
    "case_id", "appellant_id", "created_at", "reason", "original_decision", "status",
    "decision_reason", "decided_by", "decided_at", "thread_id", "starter_message_id",
}


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
    existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")


def init_db() -> None:
    with closing(connect()) as conn:
        conn.executescript(SCHEMA)
        # Databases created by version 1.0.0 have no case_type column.
        _ensure_column(conn, "cases", "case_type", "case_type TEXT NOT NULL DEFAULT 'scam'")
        conn.commit()


def create_case(**fields) -> int:
    unknown = set(fields) - CASE_COLUMNS
    if unknown:
        raise ValueError(f"Unknown case columns: {sorted(unknown)}")
    fields.setdefault("created_at", int(time.time()))
    columns = ", ".join(fields)
    marks = ", ".join("?" for _ in fields)
    with closing(connect()) as conn:
        cur = conn.execute(f"INSERT INTO cases ({columns}) VALUES ({marks})", tuple(fields.values()))
        conn.commit()
        return int(cur.lastrowid)


def update_case(case_id: int, **fields) -> None:
    if not fields:
        return
    unknown = set(fields) - CASE_COLUMNS
    if unknown:
        raise ValueError(f"Unknown case columns: {sorted(unknown)}")
    assignments = ", ".join(f"{name} = ?" for name in fields)
    with closing(connect()) as conn:
        conn.execute(f"UPDATE cases SET {assignments} WHERE id = ?", (*fields.values(), case_id))
        conn.commit()


def get_case(case_id: int) -> Optional[sqlite3.Row]:
    with closing(connect()) as conn:
        return conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()


def open_cases_for_reporter(reporter_id: int) -> list[sqlite3.Row]:
    with closing(connect()) as conn:
        return conn.execute(
            "SELECT * FROM cases WHERE reporter_id = ? AND status IN (?, ?) ORDER BY id",
            (reporter_id, *OPEN_STATUSES),
        ).fetchall()


def cases_for_suspect(suspect_id: int, exclude_id: Optional[int] = None, limit: int = 10) -> list[sqlite3.Row]:
    with closing(connect()) as conn:
        return conn.execute(
            "SELECT * FROM cases WHERE suspect_id = ? AND id != ? ORDER BY id DESC LIMIT ?",
            (suspect_id, exclude_id if exclude_id is not None else -1, limit),
        ).fetchall()


def reporter_stats(reporter_id: int) -> tuple[int, int]:
    """Returns (total reports filed, reports dismissed)."""
    with closing(connect()) as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS total, "
            "COALESCE(SUM(CASE WHEN decision = ? THEN 1 ELSE 0 END), 0) AS dismissed "
            "FROM cases WHERE reporter_id = ?",
            (DECISION_DISMISSED, reporter_id),
        ).fetchone()
        return int(row["total"]), int(row["dismissed"])


def reports_in_last(reporter_id: int, seconds: int) -> int:
    cutoff = int(time.time()) - seconds
    with closing(connect()) as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM cases WHERE reporter_id = ? AND created_at >= ?",
            (reporter_id, cutoff),
        ).fetchone()
        return int(row["n"])


def add_event(case_id: int, actor_id: Optional[int], kind: str, text: str = "") -> None:
    with closing(connect()) as conn:
        conn.execute(
            "INSERT INTO case_events (case_id, ts, actor_id, kind, text) VALUES (?, ?, ?, ?, ?)",
            (case_id, int(time.time()), actor_id, kind, text),
        )
        conn.commit()


def list_events(case_id: int) -> list[sqlite3.Row]:
    with closing(connect()) as conn:
        return conn.execute(
            "SELECT * FROM case_events WHERE case_id = ? ORDER BY id", (case_id,)
        ).fetchall()


# ------------------------------------------------------------------------------
# Decisions
# ------------------------------------------------------------------------------
def action_decision(actions: Iterable[str]) -> str:
    chosen = set(actions)
    return DECISION_ACTION_PREFIX + " " + ", ".join(a for a in ACTION_ORDER if a in chosen)


def decision_is_action(decision: Optional[str]) -> bool:
    return bool(decision) and decision.startswith(DECISION_ACTION_PREFIX)


def parse_decision_actions(decision: Optional[str]) -> set[str]:
    """Which actions a stored decision applied. Understands keys and older label text."""
    if not decision_is_action(decision):
        return set()
    found: set[str] = set()
    for part in decision[len(DECISION_ACTION_PREFIX):].split(","):
        part = part.strip().lower()
        if part in ACTION_LABELS:
            found.add(part)
        elif part in _LABEL_TO_ACTION:
            found.add(_LABEL_TO_ACTION[part])
    return found & set(ACTION_ORDER)


def decision_label(decision: Optional[str]) -> str:
    if not decision:
        return "—"
    if decision == DECISION_DISMISSED:
        return "Dismissed (not applicable)"
    if decision.startswith(DECISION_OVERTURNED):
        return "Overturned on appeal"
    if decision_is_action(decision):
        actions = parse_decision_actions(decision)
        names = [ACTION_LABELS[a] for a in ACTION_ORDER if a in actions]
        return "Action: " + (", ".join(names) if names else "none")
    return decision


# ------------------------------------------------------------------------------
# Appeals
# ------------------------------------------------------------------------------
def create_appeal(**fields) -> int:
    unknown = set(fields) - APPEAL_COLUMNS
    if unknown:
        raise ValueError(f"Unknown appeal columns: {sorted(unknown)}")
    fields.setdefault("created_at", int(time.time()))
    columns = ", ".join(fields)
    marks = ", ".join("?" for _ in fields)
    with closing(connect()) as conn:
        cur = conn.execute(f"INSERT INTO appeals ({columns}) VALUES ({marks})", tuple(fields.values()))
        conn.commit()
        return int(cur.lastrowid)


def update_appeal(appeal_id: int, **fields) -> None:
    if not fields:
        return
    unknown = set(fields) - APPEAL_COLUMNS
    if unknown:
        raise ValueError(f"Unknown appeal columns: {sorted(unknown)}")
    assignments = ", ".join(f"{name} = ?" for name in fields)
    with closing(connect()) as conn:
        conn.execute(f"UPDATE appeals SET {assignments} WHERE id = ?", (*fields.values(), appeal_id))
        conn.commit()


def get_appeal(appeal_id: int) -> Optional[sqlite3.Row]:
    with closing(connect()) as conn:
        return conn.execute("SELECT * FROM appeals WHERE id = ?", (appeal_id,)).fetchone()


def appeal_for_case(case_id: int) -> Optional[sqlite3.Row]:
    with closing(connect()) as conn:
        return conn.execute(
            "SELECT * FROM appeals WHERE case_id = ? ORDER BY id DESC LIMIT 1", (case_id,)
        ).fetchone()


def delete_appeal(appeal_id: int) -> None:
    """Only used to roll back an appeal whose forum post could not be created."""
    with closing(connect()) as conn:
        conn.execute("DELETE FROM appeals WHERE id = ?", (appeal_id,))
        conn.commit()


def can_appeal(case, user_id: int) -> Optional[str]:
    """Returns None if the user may appeal this case, otherwise a reason to show them.

    The message is deliberately the same whether the case doesn't exist, belongs to
    someone else or isn't appealable, so case numbers can't be probed.
    """
    generic = "I couldn't find a case against your account that can be appealed with that number."
    if case is None or case["suspect_id"] != user_id:
        return generic
    if case["status"] != STATUS_CLOSED or not decision_is_action(case["decision"]):
        return generic
    if appeal_for_case(case["id"]) is not None:
        return "That case has already been appealed. Each case can only be appealed once."
    return None


_APPEAL_RE = re.compile(r"^\s*appeal\s+#?(\d+)\b\s*(.*)$", re.IGNORECASE | re.DOTALL)


def parse_appeal_message(text: str) -> Optional[tuple[int, str]]:
    """'appeal #12 my account was hacked' -> (12, 'my account was hacked')."""
    match = _APPEAL_RE.match(text or "")
    if not match:
        return None
    return int(match.group(1)), match.group(2).strip()


# ------------------------------------------------------------------------------
# Per-server settings (honeypot)
# ------------------------------------------------------------------------------
def _check_honeypot_action(action: str) -> None:
    if action not in HONEYPOT_ACTIONS:
        raise ValueError(f"Unknown honeypot action: {action!r}")


def get_guild_settings(guild_id: int) -> Optional[sqlite3.Row]:
    with closing(connect()) as conn:
        return conn.execute("SELECT * FROM guild_settings WHERE guild_id = ?", (guild_id,)).fetchone()


def all_guild_settings() -> list[sqlite3.Row]:
    with closing(connect()) as conn:
        return conn.execute("SELECT * FROM guild_settings").fetchall()


def set_honeypot(guild_id: int, channel_id: int, action: str, notice_message_id: Optional[int] = None) -> None:
    _check_honeypot_action(action)
    with closing(connect()) as conn:
        conn.execute(
            "INSERT INTO guild_settings (guild_id, honeypot_channel_id, honeypot_action, honeypot_notice_message_id) "
            "VALUES (?, ?, ?, ?) ON CONFLICT(guild_id) DO UPDATE SET "
            "honeypot_channel_id = excluded.honeypot_channel_id, "
            "honeypot_action = excluded.honeypot_action, "
            "honeypot_notice_message_id = excluded.honeypot_notice_message_id",
            (guild_id, channel_id, action, notice_message_id),
        )
        conn.commit()


def set_honeypot_action(guild_id: int, action: str) -> bool:
    """Changes the punishment of an existing honeypot. Returns False if none is set up."""
    _check_honeypot_action(action)
    with closing(connect()) as conn:
        cur = conn.execute(
            "UPDATE guild_settings SET honeypot_action = ? WHERE guild_id = ? AND honeypot_channel_id IS NOT NULL",
            (action, guild_id),
        )
        conn.commit()
        return cur.rowcount > 0


def clear_honeypot(guild_id: int) -> None:
    """Turns the honeypot off. The row stays so older name-based traps don't switch back on."""
    with closing(connect()) as conn:
        conn.execute(
            "INSERT INTO guild_settings (guild_id, honeypot_channel_id, honeypot_action, honeypot_notice_message_id) "
            "VALUES (?, NULL, ?, NULL) ON CONFLICT(guild_id) DO UPDATE SET "
            "honeypot_channel_id = NULL, honeypot_notice_message_id = NULL",
            (guild_id, DEFAULT_HONEYPOT_ACTION),
        )
        conn.commit()


def clean_channel_name(raw: Optional[str], default: str = DEFAULT_HONEYPOT_NAME) -> str:
    name = re.sub(r"\s+", "-", (raw or "").strip().lower())
    name = name.lstrip("#")
    name = re.sub(r"[\x00-\x1f\x7f]", "", name)
    name = re.sub(r"-{2,}", "-", name)[:100].strip("-")
    return name or default


def honeypot_notice(action: str) -> str:
    return (
        "**NOTICE:** This channel is an automated security trap.\n\n"
        "• **Human members:** do **NOT** send messages here!\n"
        "• **Bots and violators:** any message posted here is instantly deleted and the "
        f"sender will be **{HONEYPOT_PHRASES[action]}**."
    )


def honeypot_topic(action: str) -> str:
    return f"🚨 SECURITY HONEYPOT: anyone who posts here is punished automatically ({HONEYPOT_ACTIONS[action]})."


# ------------------------------------------------------------------------------
# Blacklist file (kept compatible with the original scammers.json format)
# ------------------------------------------------------------------------------
def load_scammers() -> dict:
    if not os.path.exists(SCAMMER_FILE):
        return {"scammers": []}
    try:
        with open(SCAMMER_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {"scammers": []}
    if not isinstance(data, dict) or not isinstance(data.get("scammers"), list):
        return {"scammers": []}
    return data


def save_scammers(data: dict) -> None:
    directory = os.path.dirname(os.path.abspath(SCAMMER_FILE))
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".scammers-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        os.replace(tmp_path, SCAMMER_FILE)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


def is_blacklisted(user_id: int) -> bool:
    uid = str(user_id)
    return any(str(e.get("user_id")) == uid for e in load_scammers()["scammers"])


def blacklist_add(user_id: int, reason: str, case_id: Optional[int] = None, case_type: Optional[str] = None) -> bool:
    """Returns False if the user was already listed."""
    data = load_scammers()
    uid = str(user_id)
    if any(str(e.get("user_id")) == uid for e in data["scammers"]):
        return False
    entry: dict = {"user_id": uid, "reason": reason}
    if case_id is not None:
        entry["case_id"] = case_id
    if case_type:
        entry["type"] = case_type
    data["scammers"].append(entry)
    save_scammers(data)
    return True


def blacklist_remove(user_id: int) -> bool:
    """Returns False if the user wasn't listed."""
    data = load_scammers()
    uid = str(user_id)
    kept = [e for e in data["scammers"] if str(e.get("user_id")) != uid]
    if len(kept) == len(data["scammers"]):
        return False
    data["scammers"] = kept
    save_scammers(data)
    return True


def blacklist_entries() -> list[dict]:
    """Blacklist entries that have a numeric ID.

    Each is {"user_id": int, "reason": str, "case_id": int | None, "type": str | None}.
    """
    entries = []
    for e in load_scammers()["scammers"]:
        if not isinstance(e, dict):
            continue
        try:
            uid = int(str(e.get("user_id", "")).strip())
        except ValueError:
            continue
        case_id = e.get("case_id")
        entries.append({
            "user_id": uid,
            "reason": str(e.get("reason", "")),
            "case_id": case_id if isinstance(case_id, int) else None,
            "type": e.get("type"),
        })
    return entries


# ------------------------------------------------------------------------------
# Pre-ban opt-in (servers that let CyberBot ban blacklisted IDs before they join)
# ------------------------------------------------------------------------------
def set_autoban(guild_id: int, enabled: bool, user_id: Optional[int] = None) -> None:
    # A separate table on purpose: a guild_settings row means "the honeypot was configured here".
    with closing(connect()) as conn:
        if enabled:
            conn.execute(
                "INSERT INTO autoban_guilds (guild_id, enabled_by, enabled_at) VALUES (?, ?, ?) "
                "ON CONFLICT(guild_id) DO UPDATE SET enabled_by = excluded.enabled_by, enabled_at = excluded.enabled_at",
                (guild_id, user_id, int(time.time())),
            )
        else:
            conn.execute("DELETE FROM autoban_guilds WHERE guild_id = ?", (guild_id,))
        conn.commit()


def autoban_enabled(guild_id: int) -> bool:
    with closing(connect()) as conn:
        return conn.execute("SELECT 1 FROM autoban_guilds WHERE guild_id = ?", (guild_id,)).fetchone() is not None


def autoban_guild_ids() -> list[int]:
    with closing(connect()) as conn:
        return [int(r["guild_id"]) for r in conn.execute("SELECT guild_id FROM autoban_guilds ORDER BY guild_id")]


# ------------------------------------------------------------------------------
# Text helpers
# ------------------------------------------------------------------------------
_ID_RE = re.compile(r"\d{15,20}")
_CASE_REF_RE = re.compile(r"^\s*#(\d+)\b\s*(.*)$", re.DOTALL)


def clip(text: str, limit: int) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return text[: max(limit - 1, 0)] + "…"


def code_block(text: str, limit: int = 1800) -> str:
    """Wrap untrusted text in a code block so links, mentions and markdown stay inert."""
    safe = (text or "").replace("```", "'''")
    return "```\n" + clip(safe, limit) + "\n```"


def extract_user_id(raw: str) -> Optional[int]:
    """Pull a Discord user ID out of a bare ID or a <@id> mention."""
    match = _ID_RE.search(raw or "")
    return int(match.group(0)) if match else None


def parse_case_ref(text: str) -> tuple[Optional[int], str]:
    """'#12 more info' -> (12, 'more info'); anything else -> (None, text.strip())."""
    match = _CASE_REF_RE.match(text or "")
    if match:
        return int(match.group(1)), match.group(2).strip()
    return None, (text or "").strip()


def chunk_sizes(sizes: list[int], limit: int, max_count: int = 10) -> tuple[list[list[int]], list[int]]:
    """Group item indices into upload batches under a size limit.

    Returns (groups, oversized) where oversized holds indices that can never fit.
    """
    groups: list[list[int]] = []
    oversized: list[int] = []
    current: list[int] = []
    total = 0
    for index, size in enumerate(sizes):
        if size > limit:
            oversized.append(index)
            continue
        if current and (total + size > limit or len(current) >= max_count):
            groups.append(current)
            current, total = [], 0
        current.append(index)
        total += size
    if current:
        groups.append(current)
    return groups, oversized


_WHY = {
    CASE_SCAM: "suspected scam or fraud",
    CASE_BULLYING: "cyberbullying or harassment",
    CASE_OTHER: "behaviour that breaks our community safety rules",
}


def default_appeal_text(case_id: int) -> str:
    return (
        "If you think this was a mistake, you can appeal once. Press the Appeal button below, "
        f"or reply to this message with `appeal #{case_id}` followed by your explanation, "
        "or use the /appeal command. Appeals are reviewed by staff."
    )


def default_dm_text(case_id: int, case_type: str, actions: Iterable[str], appeal_text: Optional[str] = None) -> str:
    chosen = set(actions)
    parts = []
    if ACTION_BAN in chosen:
        parts.append(f"You have been banned from {COMMUNITY_NAME}.")
    if ACTION_BLACKLIST in chosen:
        parts.append(
            "You have also been added to the CyberBot blacklist, which other servers use to protect their communities."
            if ACTION_BAN in chosen
            else "You have been added to the CyberBot blacklist, which other servers use to protect their communities."
        )
    if not parts:
        parts.append(f"This is an official warning from {COMMUNITY_NAME}.")
    why = _WHY.get(case_type, _WHY[CASE_OTHER])
    return (
        " ".join(parts)
        + f"\n\nThis follows a reviewed report of {why}.\n\n"
        + (appeal_text or default_appeal_text(case_id))
        + f"\n\nCase reference: #{case_id}"
    )


def default_public_text(case_id: int, suspect_label: str, suspect_id: int) -> str:
    return (
        f"⚠️ **Scam warning:** {suspect_label} (`{suspect_id}`) has been confirmed as a scammer "
        "following a reviewed report. Do not trade with them, click their links or send them money. "
        f"If you have dealt with this user, contact staff. (Case #{case_id})"
    )


def reporter_outcome_text(case_id: int, note: str = "") -> str:
    text = (
        f"Your report (case #{case_id}) has been reviewed and closed. "
        "Thank you for helping keep the community safe."
    )
    if note.strip():
        text += f"\n\nReviewer note: {note.strip()}"
    return text


def appeal_outcome_text(case_id: int, overturned: bool, note: str = "", unbanned: bool = False) -> str:
    if overturned:
        text = f"Your appeal for case #{case_id} was reviewed and **accepted**. The action against you has been lifted."
        if unbanned:
            text += f" You can rejoin {COMMUNITY_NAME} if you have an invite link."
    else:
        text = f"Your appeal for case #{case_id} was reviewed and the original decision **stands**."
    if note.strip():
        text += f"\n\nReviewer note: {note.strip()}"
    return text


def ban_reason(case_id: int, reason: str) -> str:
    return clip(f"[CyberBot Case #{case_id}] {reason}", 512)


def preban_reason(case_id: Optional[int]) -> str:
    """Ban reason used in other servers. Never includes the reviewer's internal reason."""
    if case_id is None:
        return "[CyberBot Blacklist] Pre-ban: user is on the CyberBot blacklist"
    return f"[CyberBot Case #{case_id}] Pre-ban: user is on the CyberBot blacklist"


def ban_is_ours(reason: Optional[str], case_id: int) -> bool:
    """True if a ban's reason shows CyberBot placed it for this case (so an appeal may lift it)."""
    return bool(reason) and reason.startswith(f"[CyberBot Case #{case_id}]")


# ------------------------------------------------------------------------------
# Punishment runner
# ------------------------------------------------------------------------------
class ActionError(Exception):
    """Raised by an action implementation with a reviewer-readable explanation."""


@dataclass
class ActionResult:
    action: str
    ok: bool
    detail: str


def effective_actions(actions: Iterable[str]) -> set[str]:
    """A ban or blacklist always comes with a DM to the person, whenever possible."""
    chosen = set(actions)
    if chosen & {ACTION_BAN, ACTION_BLACKLIST}:
        chosen.add(ACTION_DM)
    return chosen


def public_warning_allowed(case_type: Optional[str]) -> bool:
    """Naming someone publicly is only for scams, never for harassment cases."""
    return case_type == CASE_SCAM


async def _attempt(action: str, awaitable) -> ActionResult:
    try:
        return ActionResult(action, True, await awaitable)
    except ActionError as exc:
        return ActionResult(action, False, str(exc))
    except Exception as exc:  # keep going; one failure must not block the others
        return ActionResult(action, False, f"Unexpected error: {exc!r}")


async def run_actions(io, case, actions: Iterable[str], reason: str, dm_text: str, public_text: str) -> list[ActionResult]:
    """Run the chosen actions in a safe order and report each outcome.

    `io` supplies is_protected, dm_suspect, post_public, blacklist and ban.
    """
    wanted = [a for a in ACTION_ORDER if a in effective_actions(actions)]
    case_id = case["id"]
    suspect_id = case["suspect_id"]
    case_type = case["case_type"]

    if await io.is_protected(suspect_id):
        return [ActionResult(a, False, "Refused: the target is the bot or its owner.") for a in wanted]

    results: list[ActionResult] = []
    for action in wanted:
        if action == ACTION_DM:
            awaitable = io.dm_suspect(suspect_id, dm_text, case_id)
        elif action == ACTION_PUBLIC:
            if not public_warning_allowed(case_type):
                results.append(ActionResult(action, False, "Public warnings are only available for scam cases."))
                continue
            awaitable = io.post_public(public_text, case_id)
        elif action == ACTION_BLACKLIST:
            awaitable = io.blacklist(suspect_id, reason, case_id, case_type)
        else:
            awaitable = io.ban(suspect_id, ban_reason(case_id, reason))
        results.append(await _attempt(action, awaitable))
    return results


async def run_reversal(io, case) -> list[ActionResult]:
    """Undo the ban and blacklist entry a case's decision applied (used when an appeal is accepted)."""
    applied = parse_decision_actions(case["decision"])
    case_id = case["id"]
    results: list[ActionResult] = []
    if ACTION_BAN in applied:
        results.append(await _attempt(
            ACTION_UNBAN, io.unban(case["suspect_id"], clip(f"[CyberBot] Appeal accepted for case #{case_id}", 512))
        ))
    if ACTION_BLACKLIST in applied:
        results.append(await _attempt(ACTION_UNBLACKLIST, io.unblacklist(case["suspect_id"])))
    return results


def describe_results(results: Iterable[ActionResult]) -> str:
    lines = []
    for r in results:
        label = ACTION_LABELS.get(r.action, r.action)
        lines.append(f"{'✅' if r.ok else '❌'} **{label}** — {r.detail}")
    return "\n".join(lines)
