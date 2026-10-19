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

REPORT_LIMIT_PER_HOUR = 5
THREAD_ARCHIVE_MINUTES = 10080  # 7 days

STATUS_OPEN = "open"
STATUS_NEEDS_INFO = "needs_info"
STATUS_CLOSED = "closed"
OPEN_STATUSES = (STATUS_OPEN, STATUS_NEEDS_INFO)

DECISION_DISMISSED = "dismissed"

ACTION_DM = "dm_warning"
ACTION_PUBLIC = "public_warning"
ACTION_BLACKLIST = "blacklist"
ACTION_BAN = "ban"
# DM first (a ban can remove the shared server the DM needs), ban last.
ACTION_ORDER = (ACTION_DM, ACTION_PUBLIC, ACTION_BLACKLIST, ACTION_BAN)
ACTION_LABELS = {
    ACTION_DM: "DM warning",
    ACTION_PUBLIC: "Public warning",
    ACTION_BLACKLIST: "Blacklist",
    ACTION_BAN: "Ban",
}


def env_int(name: str, default: Optional[int] = None) -> Optional[int]:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip())
    except ValueError:
        return default


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
    reporter_dm_ok INTEGER
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
"""

CASE_COLUMNS = {
    "created_at", "reporter_id", "suspect_id", "suspect_name", "source_guild_id",
    "source_channel_id", "anchor_message_id", "anchor_sent_at", "anchor_content",
    "verified", "details", "pasted_context", "status", "decision", "decision_reason",
    "decided_by", "decided_at", "thread_id", "starter_message_id", "panel_message_id",
    "reporter_dm_ok",
}


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with closing(connect()) as conn:
        conn.executescript(SCHEMA)
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


def blacklist_add(user_id: int, reason: str, case_id: Optional[int] = None) -> bool:
    """Returns False if the user was already listed."""
    data = load_scammers()
    uid = str(user_id)
    if any(str(e.get("user_id")) == uid for e in data["scammers"]):
        return False
    entry: dict = {"user_id": uid, "reason": reason}
    if case_id is not None:
        entry["case_id"] = case_id
    data["scammers"].append(entry)
    save_scammers(data)
    return True


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


def default_dm_text(case_id: int, appeal_text: str) -> str:
    return (
        "A report about your activity was reviewed by CyberByte's internal affairs team, "
        "and action was taken because it breaks our community safety rules "
        "(suspected scam or fraud).\n\n"
        f"{appeal_text}\n\n"
        f"Case reference: #{case_id}"
    )


def default_public_text(case_id: int, suspect_label: str, suspect_id: int) -> str:
    return (
        f"⚠️ **Scam warning:** {suspect_label} (`{suspect_id}`) has been blacklisted by CyberByte "
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


def ban_reason(case_id: int, reason: str) -> str:
    return clip(f"[CyberBot Case #{case_id}] {reason}", 512)


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


async def run_actions(io, case, actions: Iterable[str], reason: str, dm_text: str, public_text: str) -> list[ActionResult]:
    """Run the chosen actions in a safe order and report each outcome.

    `io` supplies is_protected, dm_suspect, post_public, blacklist and ban.
    """
    chosen = set(actions)
    wanted = [a for a in ACTION_ORDER if a in chosen]
    case_id = case["id"]
    suspect_id = case["suspect_id"]

    if await io.is_protected(suspect_id):
        return [ActionResult(a, False, "Refused: the target is the bot or its owner.") for a in wanted]

    results: list[ActionResult] = []
    for action in wanted:
        try:
            if action == ACTION_DM:
                detail = await io.dm_suspect(suspect_id, dm_text, case_id)
            elif action == ACTION_PUBLIC:
                detail = await io.post_public(public_text, case_id)
            elif action == ACTION_BLACKLIST:
                detail = await io.blacklist(suspect_id, reason, case_id)
            else:
                detail = await io.ban(suspect_id, ban_reason(case_id, reason))
            results.append(ActionResult(action, True, detail))
        except ActionError as exc:
            results.append(ActionResult(action, False, str(exc)))
        except Exception as exc:  # keep going; one failure must not block the others
            results.append(ActionResult(action, False, f"Unexpected error: {exc!r}"))
    return results


def describe_results(results: Iterable[ActionResult]) -> str:
    lines = []
    for r in results:
        label = ACTION_LABELS.get(r.action, r.action)
        lines.append(f"{'✅' if r.ok else '❌'} **{label}** — {r.detail}")
    return "\n".join(lines)
