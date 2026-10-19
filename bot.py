import asyncio
import datetime
import io
import os
import time
import traceback
from typing import Optional, Union

import discord
from discord import app_commands
from discord.ext import commands
from dotenv import load_dotenv

import cyberbot_core as core

# ------------------------------------------------------------------------------
# 1. CONFIGURATION
# ------------------------------------------------------------------------------
load_dotenv()
TOKEN = os.getenv("DISCORD_TOKEN")

# Forum channel where every report becomes its own post
REVIEW_FORUM_ID = core.env_int("REVIEW_FORUM_ID")  # required, set it in .env
# Server where bans are applied (defaults to the server that owns the review forum)
ACTION_GUILD_ID = core.env_int("CYBERBYTE_GUILD_ID")
# Channel for public warnings (optional; the option is refused if unset)
PUBLIC_WARNING_CHANNEL_ID = core.env_int("PUBLIC_WARNING_CHANNEL_ID")
# Role allowed to review cases in addition to the bot owner (optional)
REVIEWER_ROLE_ID = core.env_int("REVIEWER_ROLE_ID")
APPEAL_TEXT = os.getenv(
    "APPEAL_TEXT",
    "If you believe this was a mistake, you can appeal by contacting CyberByte staff "
    "and quoting the case number below.",
)

ALERT_CHANNEL_NAME = "cyberbot-alerts"
HONEYPOT_CHANNEL_NAME = "security-honeypot"

intents = discord.Intents.default()
intents.guilds = True
intents.guild_messages = True
intents.message_content = True  # privileged: enable in the Developer Portal
intents.members = True          # privileged: enable in the Developer Portal

NO_MENTIONS = discord.AllowedMentions.none()
HELP_TEXT = (
    "👋 I'm CyberBot. To report a scammer, right-click (or long-press) one of their messages, "
    "choose **Apps → Report to CyberBot**, and I'll open a case and message you here."
)

INFLIGHT: set = set()      # case IDs currently being decided, guards against double clicks
_help_sent: dict = {}      # user id -> last time we sent the DM help text
_startup_checked = False


def now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def utc(ts: Optional[int]) -> datetime.datetime:
    return datetime.datetime.fromtimestamp(ts or 0, tz=datetime.timezone.utc)


# ------------------------------------------------------------------------------
# 2. BOT CLASS
# ------------------------------------------------------------------------------
class CyberBot(commands.Bot):
    async def setup_hook(self):
        core.init_db()
        # Case-panel buttons carry the case number in their custom_id, so they
        # keep working after a restart without re-registering every case.
        self.add_dynamic_items(CaseButton)
        try:
            synced = await self.tree.sync()
            print(f"⚡ Synced {len(synced)} application command(s).")
        except Exception as exc:
            print(f"❌ Error syncing commands: {exc}")


bot = CyberBot(command_prefix="!", intents=intents)


# ------------------------------------------------------------------------------
# 3. SHARED HELPERS
# ------------------------------------------------------------------------------
def is_bot_owner():
    async def predicate(interaction: discord.Interaction) -> bool:
        return await interaction.client.is_owner(interaction.user)
    return app_commands.check(predicate)


async def get_review_forum() -> Optional[discord.ForumChannel]:
    if REVIEW_FORUM_ID is None:
        return None
    channel = bot.get_channel(REVIEW_FORUM_ID)
    if channel is None:
        try:
            channel = await bot.fetch_channel(REVIEW_FORUM_ID)
        except discord.HTTPException:
            return None
    return channel if isinstance(channel, discord.ForumChannel) else None


async def get_case_thread(case) -> Optional[discord.Thread]:
    if not case["thread_id"]:
        return None
    thread = bot.get_channel(case["thread_id"])
    if thread is None:
        try:
            thread = await bot.fetch_channel(case["thread_id"])
        except discord.HTTPException:
            return None
    return thread if isinstance(thread, discord.Thread) else None


async def user_is_reviewer(user) -> bool:
    try:
        if await bot.is_owner(user):
            return True
    except Exception:
        pass
    if REVIEWER_ROLE_ID is None:
        return False
    forum = await get_review_forum()
    if forum is None:
        return False
    member = forum.guild.get_member(user.id)
    if member is None:
        try:
            member = await forum.guild.fetch_member(user.id)
        except discord.HTTPException:
            return False
    return any(role.id == REVIEWER_ROLE_ID for role in member.roles)


def reviewer_only():
    async def predicate(interaction: discord.Interaction) -> bool:
        return await user_is_reviewer(interaction.user)
    return app_commands.check(predicate)


async def reply(interaction: discord.Interaction, content: str, **kwargs):
    """Send an ephemeral message whether or not the interaction was already answered."""
    if interaction.response.is_done():
        await interaction.followup.send(content, ephemeral=True, **kwargs)
    else:
        await interaction.response.send_message(content, ephemeral=True, **kwargs)


async def dm_user(user_id: int, **send_kwargs) -> Optional[str]:
    """DM a user by ID. Returns None on success, otherwise a short reason."""
    try:
        user = bot.get_user(user_id) or await bot.fetch_user(user_id)
        await user.send(**send_kwargs)
        return None
    except discord.Forbidden:
        return "DMs are closed, the bot is blocked, or you share no server"
    except discord.NotFound:
        return "user not found"
    except discord.HTTPException as exc:
        return f"Discord error {exc.status}"


def is_rehostable(att: discord.Attachment) -> bool:
    """Only copy plain images into the review forum; other files could be malware."""
    ctype = (att.content_type or "").lower()
    return ctype.startswith("image/") and "svg" not in ctype


async def post_files(dest, attachments, caption: str, limit: int) -> list:
    """Download attachments and re-post them (links to originals expire).

    Returns notes describing any file that could not be copied.
    """
    files, sizes, notes = [], [], []
    for att in attachments:
        if att.size > limit:
            notes.append(f"{att.filename} (too large to copy)")
            continue
        try:
            data = await att.read()
        except discord.HTTPException:
            notes.append(f"{att.filename} (download failed)")
            continue
        files.append(discord.File(io.BytesIO(data), filename=att.filename, spoiler=att.is_spoiler()))
        sizes.append(len(data))
    groups, oversized = core.chunk_sizes(sizes, limit)
    for index, group in enumerate(groups):
        await dest.send(
            content=caption if index == 0 else None,
            files=[files[i] for i in group],
            allowed_mentions=NO_MENTIONS,
        )
    return notes


# ------------------------------------------------------------------------------
# 4. CASE EMBEDS AND FORUM TAGS
# ------------------------------------------------------------------------------
STATUS_META = {
    "open": ("Open", 0xFFA500),
    "needs_info": ("Waiting for reporter", 0x3498DB),
    "dismissed": ("Closed — not applicable", 0x95A5A6),
    "actioned": ("Closed — action taken", 0x2ECC71),
}
# Forum tags with these names (case-insensitive) are applied automatically if they exist.
STATUS_TAG_NAMES = {
    "open": "open",
    "needs_info": "needs info",
    "dismissed": "dismissed",
    "actioned": "actioned",
}


def status_key(case) -> str:
    if case["status"] == core.STATUS_CLOSED:
        return "dismissed" if case["decision"] == core.DECISION_DISMISSED else "actioned"
    return case["status"]


def pick_tags(forum: discord.ForumChannel, case) -> list:
    wanted = STATUS_TAG_NAMES[status_key(case)]
    tags = [t for t in forum.available_tags if t.name.strip().lower() == wanted]
    if not tags and forum.flags.require_tag and forum.available_tags:
        tags = [forum.available_tags[0]]  # the forum insists on a tag
    return tags


def thread_title(case) -> str:
    return f"Case #{case['id']} – {case['suspect_name'] or case['suspect_id']}"[:100]


def history_text(case) -> str:
    lines = []
    prior = core.cases_for_suspect(case["suspect_id"], exclude_id=case["id"], limit=6)
    if prior:
        lines.append("Earlier cases against this user: " + ", ".join(f"#{r['id']}" for r in prior))
    else:
        lines.append("No earlier cases against this user.")
    if core.is_blacklisted(case["suspect_id"]):
        lines.append("⛔ Already on the blacklist.")
    total, dismissed = core.reporter_stats(case["reporter_id"])
    lines.append(f"Reporter has filed {total} report(s), {dismissed} dismissed.")
    return "\n".join(lines)


def starter_embed(case) -> discord.Embed:
    label, color = STATUS_META[status_key(case)]
    embed = discord.Embed(
        title=f"Case #{case['id']} — {label}",
        color=color,
        timestamp=utc(case["created_at"]),
    )
    suspect_label = case["suspect_name"] or "Unknown user"
    embed.add_field(
        name="Suspect",
        value=f"{suspect_label}\nID `{case['suspect_id']}`\n<@{case['suspect_id']}>",
        inline=True,
    )
    embed.add_field(
        name="Reporter",
        value=f"<@{case['reporter_id']}>\nID `{case['reporter_id']}`",
        inline=True,
    )
    embed.add_field(
        name="Evidence",
        value="✅ Message verified by Discord" if case["verified"] else "⚠️ Unverified (reporter's word only)",
        inline=True,
    )
    embed.add_field(name="History", value=core.clip(history_text(case), 1000), inline=False)
    if case["status"] == core.STATUS_CLOSED and case["decided_at"]:
        decision = (
            f"**{case['decision']}**\n"
            f"By <@{case['decided_by']}> on <t:{case['decided_at']}:f>\n"
            f"Reason: {case['decision_reason'] or '—'}"
        )
        embed.add_field(name="Decision", value=core.clip(decision, 1000), inline=False)
    else:
        embed.description = "Review the evidence in this post, then use the buttons below."
    embed.set_footer(text="CyberBot case file")
    return embed


def verified_embed(case, anchor: discord.Message) -> discord.Embed:
    author = anchor.author
    embed = discord.Embed(
        title="✅ Verified message — delivered by Discord",
        color=0x2ECC71,
        timestamp=anchor.created_at,
    )
    embed.description = core.code_block(anchor.content or "(no text content)", 3800)
    embed.add_field(
        name="Author",
        value=f"{author.display_name} (@{author.name})\nID `{author.id}`",
        inline=True,
    )
    if case["source_guild_id"] is None:
        where = "Direct message / group DM"
    else:
        where = f"Server `{case['source_guild_id']}`\nChannel `{case['source_channel_id']}`"
    embed.add_field(name="Where", value=where, inline=True)
    if anchor.attachments:
        lines = []
        for att in anchor.attachments:
            note = "copied below" if is_rehostable(att) else "not copied (file type)"
            lines.append(f"• {att.filename} — {att.size // 1024} KB — {note}")
        embed.add_field(
            name=f"Attachments ({len(anchor.attachments)})",
            value=core.clip("\n".join(lines), 1000),
            inline=False,
        )
    embed.set_footer(text="Shown in a code block so links in it can't be clicked.")
    return embed


def statement_embed(title: str, text: str, footer: str) -> discord.Embed:
    embed = discord.Embed(title=title, description=core.clip(text, 4000), color=0xF1C40F)
    embed.set_footer(text=footer)
    return embed


def reporter_receipt_embed(case_id: int) -> discord.Embed:
    embed = discord.Embed(
        title=f"✅ Report received — case #{case_id}",
        description=(
            "A reviewer will look at it, usually within a day. If we need more information "
            "we'll message you here."
        ),
        color=0x2ECC71,
    )
    embed.add_field(
        name="Add proof any time",
        value=(
            f"Reply here starting with `#{case_id}` (attach screenshots if you have them), "
            f"or use `/report-update case_id:{case_id}`."
        ),
        inline=False,
    )
    embed.add_field(
        name="What we store",
        value=(
            "Your report, the reported message and anything you add are stored by CyberBot "
            "and shown to the review team."
        ),
        inline=False,
    )
    return embed


# ------------------------------------------------------------------------------
# 5. CASE CREATION
# ------------------------------------------------------------------------------
def check_report_allowed(reporter_id: int, suspect_id: int) -> Optional[str]:
    if suspect_id == reporter_id:
        return "❌ You can't report yourself."
    if bot.user is not None and suspect_id == bot.user.id:
        return "❌ You can't report the bot."
    if core.reports_in_last(reporter_id, 3600) >= core.REPORT_LIMIT_PER_HOUR:
        return "❌ You've filed several reports in the last hour. Please wait a bit before sending more."
    return None


async def open_case_post(forum: discord.ForumChannel, case):
    kwargs = dict(
        name=thread_title(case),
        auto_archive_duration=core.THREAD_ARCHIVE_MINUTES,
        embed=starter_embed(case),
        view=build_panel_view(case["id"]),
        allowed_mentions=NO_MENTIONS,
    )
    tags = pick_tags(forum, case)
    if tags:
        try:
            return await forum.create_thread(applied_tags=tags, **kwargs)
        except discord.HTTPException:
            # e.g. the tag is moderator-only; try again without it
            kwargs["view"] = build_panel_view(case["id"])
    return await forum.create_thread(**kwargs)


async def post_case_evidence(thread: discord.Thread, limit: int, case, anchor, proofs) -> None:
    to_copy = []
    if anchor is not None:
        await thread.send(embed=verified_embed(case, anchor), allowed_mentions=NO_MENTIONS)
        to_copy += [a for a in anchor.attachments if is_rehostable(a)]
    else:
        await thread.send(
            embed=discord.Embed(
                title="⚠️ No Discord-verified message",
                description=(
                    "This report was filed without selecting a message, so everything in this "
                    "post comes from the reporter and is unverified."
                ),
                color=0xF1C40F,
            ),
            allowed_mentions=NO_MENTIONS,
        )
    await thread.send(
        embed=statement_embed(
            "📝 Reporter's account (unverified)",
            case["details"] or "(nothing written)",
            "Written by the reporter. Not verified by Discord.",
        ),
        allowed_mentions=NO_MENTIONS,
    )

    pasted = (case["pasted_context"] or "").strip()
    if pasted:
        if len(pasted) <= 1800:
            await thread.send(
                content="**Pasted conversation (unverified):**\n" + core.code_block(pasted, 1800),
                allowed_mentions=NO_MENTIONS,
            )
        else:
            await thread.send(
                content="**Pasted conversation (unverified)** — attached as a file because it is long:",
                file=discord.File(
                    io.BytesIO(pasted.encode("utf-8")),
                    filename=f"case-{case['id']}-pasted-conversation.txt",
                ),
                allowed_mentions=NO_MENTIONS,
            )

    to_copy += [a for a in proofs if is_rehostable(a)]
    if to_copy:
        notes = await post_files(thread, to_copy, "**Evidence images (re-hosted copies):**", limit)
        if notes:
            await thread.send(
                content="⚠️ Could not copy: " + ", ".join(notes), allowed_mentions=NO_MENTIONS
            )


async def create_case_from_report(
    *,
    reporter,
    suspect_id: int,
    suspect_name: Optional[str],
    details: str,
    pasted_context: str,
    source_guild_id: Optional[int],
    source_channel_id: Optional[int],
    anchor: Optional[discord.Message] = None,
    proofs: Optional[list] = None,
):
    """Returns (case_id, error, dm_error)."""
    forum = await get_review_forum()
    if forum is None:
        return None, "The review forum isn't reachable right now. Please tell a staff member.", None
    proofs = proofs or []

    if suspect_name is None:
        try:
            suspect_name = (await bot.fetch_user(suspect_id)).name
        except discord.HTTPException:
            suspect_name = None

    fields = dict(
        reporter_id=reporter.id,
        suspect_id=suspect_id,
        suspect_name=suspect_name,
        source_guild_id=source_guild_id,
        source_channel_id=source_channel_id,
        details=details,
        pasted_context=pasted_context or "",
        verified=1 if anchor is not None else 0,
        status=core.STATUS_OPEN,
    )
    if anchor is not None:
        fields.update(
            anchor_message_id=anchor.id,
            anchor_sent_at=int(anchor.created_at.timestamp()),
            anchor_content=anchor.content or "",
        )
    case_id = core.create_case(**fields)
    case = core.get_case(case_id)

    try:
        created = await open_case_post(forum, case)
    except discord.HTTPException as exc:
        print(f"❌ Could not create forum post for case #{case_id}: {exc}")
        core.update_case(case_id, status=core.STATUS_CLOSED, decision=f"error: post failed ({exc.status})")
        return None, "I couldn't create the case post (check my permissions in the review forum).", None

    thread, first_message = created.thread, created.message
    core.update_case(
        case_id,
        thread_id=thread.id,
        starter_message_id=first_message.id,
        panel_message_id=first_message.id,
    )
    case = core.get_case(case_id)

    try:
        await post_case_evidence(thread, forum.guild.filesize_limit, case, anchor, proofs)
    except discord.HTTPException as exc:
        print(f"⚠️ Evidence for case #{case_id} was only partly posted: {exc}")
        try:
            await thread.send(
                content=f"⚠️ Some evidence could not be posted (Discord error {exc.status}).",
                allowed_mentions=NO_MENTIONS,
            )
        except discord.HTTPException:
            pass

    core.add_event(case_id, reporter.id, "created", "verified" if anchor is not None else "unverified")
    dm_error = await dm_user(reporter.id, embed=reporter_receipt_embed(case_id))
    core.update_case(case_id, reporter_dm_ok=0 if dm_error else 1)
    return case_id, None, dm_error


async def refresh_case_ui(case_id: int) -> None:
    """Re-render the case's first message (summary + buttons) and its status tag.

    Always call this after posting something to the thread: posting un-archives
    an archived forum post, and edits to an archived post are refused.
    """
    case = core.get_case(case_id)
    if case is None:
        return
    thread = await get_case_thread(case)
    if thread is None:
        return
    closed = case["status"] == core.STATUS_CLOSED
    try:
        await thread.get_partial_message(case["starter_message_id"]).edit(
            embed=starter_embed(case),
            view=build_panel_view(case_id, disabled=closed),
        )
    except discord.HTTPException as exc:
        print(f"⚠️ Could not refresh case #{case_id} summary: {exc}")

    forum = await get_review_forum()
    if forum is None:
        return
    status_names = set(STATUS_TAG_NAMES.values())
    keep = [t for t in thread.applied_tags if t.name.strip().lower() not in status_names]
    new_tags = (keep + pick_tags(forum, case))[:5]
    if {t.id for t in new_tags} != {t.id for t in thread.applied_tags}:
        try:
            await thread.edit(applied_tags=new_tags)
        except discord.HTTPException as exc:
            print(f"⚠️ Could not update tags on case #{case_id}: {exc}")


async def notify_reporter_outcome(case, note: str = "") -> Optional[str]:
    embed = discord.Embed(
        title=f"Case #{case['id']} — reviewed",
        description=core.reporter_outcome_text(case["id"], note),
        color=0x2ECC71,
    )
    error = await dm_user(case["reporter_id"], embed=embed)
    if error:
        core.add_event(case["id"], None, "reporter_notify_failed", error)
    return error


# ------------------------------------------------------------------------------
# 6. REPORT INTAKE: MENUS, MODAL, /report
# ------------------------------------------------------------------------------
class ReportModal(discord.ui.Modal, title="Report to CyberBot"):
    details = discord.ui.TextInput(
        label="What happened?",
        style=discord.TextStyle.paragraph,
        placeholder="Briefly explain what they did (scam, phishing, impersonation...).",
        required=True,
        max_length=1000,
    )
    context = discord.ui.TextInput(
        label="Paste the rest of the conversation",
        style=discord.TextStyle.paragraph,
        placeholder="Optional. Paste the conversation here (counts as unverified).",
        required=False,
        max_length=4000,
    )

    def __init__(self, anchor: Optional[discord.Message] = None, suspect=None):
        super().__init__()
        self.anchor = anchor
        self.suspect = suspect

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        if self.anchor is not None:
            suspect_id, suspect_name = self.anchor.author.id, self.anchor.author.name
        else:
            suspect_id, suspect_name = self.suspect.id, self.suspect.name

        case_id, error, dm_error = await create_case_from_report(
            reporter=interaction.user,
            suspect_id=suspect_id,
            suspect_name=suspect_name,
            details=self.details.value.strip(),
            pasted_context=self.context.value.strip(),
            source_guild_id=interaction.guild_id,
            source_channel_id=interaction.channel_id,
            anchor=self.anchor,
        )
        if error:
            await interaction.followup.send(f"❌ {error}", ephemeral=True)
            return
        text = f"✅ Report submitted as **case #{case_id}**."
        if dm_error:
            text += (
                f"\n⚠️ I couldn't DM you ({dm_error}). To add proof later, use "
                f"`/report-update case_id:{case_id}`. Turn on DMs if you want follow-up questions."
            )
        else:
            text += "\nI've sent you a DM with the details. You can reply there to add more proof."
        await interaction.followup.send(text, ephemeral=True)

    async def on_error(self, interaction: discord.Interaction, error: Exception):
        traceback.print_exception(type(error), error, error.__traceback__)
        await reply(interaction, "❌ Something went wrong while filing your report.")


@bot.tree.context_menu(name="Report to CyberBot")
@app_commands.allowed_installs(guilds=True, users=True)
@app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
async def report_message_menu(interaction: discord.Interaction, message: discord.Message):
    problem = check_report_allowed(interaction.user.id, message.author.id)
    if problem:
        await interaction.response.send_message(problem, ephemeral=True)
        return
    await interaction.response.send_modal(ReportModal(anchor=message))


@bot.tree.context_menu(name="Report user to CyberBot")
@app_commands.allowed_installs(guilds=True, users=True)
@app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
async def report_user_menu(interaction: discord.Interaction, user: Union[discord.Member, discord.User]):
    problem = check_report_allowed(interaction.user.id, user.id)
    if problem:
        await interaction.response.send_message(problem, ephemeral=True)
        return
    await interaction.response.send_modal(ReportModal(suspect=user))


@bot.tree.command(
    name="report",
    description="Report a scammer. Tip: right-click a message → Apps → Report to CyberBot is more reliable.",
)
@app_commands.allowed_installs(guilds=True, users=True)
@app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
@app_commands.describe(
    suspect_id="The suspect's User ID (or a mention)",
    evidence="Explain what they did and provide details",
    proof_1="Primary screenshot proof (required)",
    proof_2="Additional screenshot (optional)",
    proof_3="Additional screenshot (optional)",
    proof_4="Additional screenshot (optional)",
)
async def report(
    interaction: discord.Interaction,
    suspect_id: str,
    evidence: app_commands.Range[str, 1, 1000],
    proof_1: discord.Attachment,
    proof_2: Optional[discord.Attachment] = None,
    proof_3: Optional[discord.Attachment] = None,
    proof_4: Optional[discord.Attachment] = None,
):
    uid = core.extract_user_id(suspect_id)
    if uid is None:
        await interaction.response.send_message(
            "❌ I need the suspect's numeric User ID. Turn on Developer Mode, right-click the user and "
            "choose Copy User ID, or use right-click → Apps → Report to CyberBot instead.",
            ephemeral=True,
        )
        return
    problem = check_report_allowed(interaction.user.id, uid)
    if problem:
        await interaction.response.send_message(problem, ephemeral=True)
        return

    proofs = [p for p in (proof_1, proof_2, proof_3, proof_4) if p is not None]
    for att in proofs:
        if not att.content_type or not att.content_type.startswith("image/"):
            await interaction.response.send_message(
                f"❌ {att.filename} isn't an image (PNG, JPG, WEBP).", ephemeral=True
            )
            return

    await interaction.response.defer(ephemeral=True, thinking=True)
    case_id, error, dm_error = await create_case_from_report(
        reporter=interaction.user,
        suspect_id=uid,
        suspect_name=None,
        details=evidence,
        pasted_context="",
        source_guild_id=interaction.guild_id,
        source_channel_id=interaction.channel_id,
        proofs=proofs,
    )
    if error:
        await interaction.followup.send(f"❌ {error}", ephemeral=True)
        return
    text = f"✅ Report submitted as **case #{case_id}** (screenshots only, so it is marked unverified)."
    if dm_error:
        text += f"\n⚠️ I couldn't DM you ({dm_error}). Use `/report-update case_id:{case_id}` to add more."
    else:
        text += "\nI've sent you a DM with the details."
    await interaction.followup.send(text, ephemeral=True)


# ------------------------------------------------------------------------------
# 7. REPORTER UPDATES: /report-update AND DM REPLIES
# ------------------------------------------------------------------------------
async def relay_reporter_update(case, user, text: str, attachments: list) -> Optional[str]:
    """Post a reporter's extra info into the case post. Returns an error string or None."""
    thread = await get_case_thread(case)
    if thread is None:
        return "I can't find the case post."
    forum = await get_review_forum()
    limit = forum.guild.filesize_limit if forum is not None else 8 * 1024 * 1024
    try:
        embed = discord.Embed(
            title="📎 Update from reporter (unverified)",
            description=core.code_block(text, 3800) if text else "(attachments only)",
            color=0xF1C40F,
            timestamp=now(),
        )
        await thread.send(embed=embed, allowed_mentions=NO_MENTIONS)
        if attachments:
            copyable = [a for a in attachments if is_rehostable(a)]
            skipped = [a.filename for a in attachments if not is_rehostable(a)]
            notes = []
            if copyable:
                notes = await post_files(thread, copyable, "**Files from the reporter (re-hosted):**", limit)
            notes += [f"{name} (not an image)" for name in skipped]
            if notes:
                await thread.send(content="⚠️ Not copied: " + ", ".join(notes), allowed_mentions=NO_MENTIONS)
    except discord.HTTPException as exc:
        return f"Discord error {exc.status} while posting"

    core.add_event(case["id"], user.id, "reporter_update", core.clip(text, 500))
    if case["status"] == core.STATUS_NEEDS_INFO:
        core.update_case(case["id"], status=core.STATUS_OPEN)
    await refresh_case_ui(case["id"])
    return None


@bot.tree.command(name="report-update", description="Add more proof or details to one of your open reports.")
@app_commands.allowed_installs(guilds=True, users=True)
@app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
@app_commands.describe(
    case_id="Your case number",
    note="More details (optional if you attach something)",
    proof_1="Screenshot (optional)",
    proof_2="Screenshot (optional)",
    proof_3="Screenshot (optional)",
)
async def report_update(
    interaction: discord.Interaction,
    case_id: int,
    note: Optional[app_commands.Range[str, 1, 1500]] = None,
    proof_1: Optional[discord.Attachment] = None,
    proof_2: Optional[discord.Attachment] = None,
    proof_3: Optional[discord.Attachment] = None,
):
    case = core.get_case(case_id)
    if case is None or case["reporter_id"] != interaction.user.id or case["status"] == core.STATUS_CLOSED:
        await interaction.response.send_message(
            f"❌ I couldn't find an open case #{case_id} filed by you.", ephemeral=True
        )
        return
    attachments = [a for a in (proof_1, proof_2, proof_3) if a is not None]
    if not note and not attachments:
        await interaction.response.send_message("❌ Add a note or at least one screenshot.", ephemeral=True)
        return
    await interaction.response.defer(ephemeral=True, thinking=True)
    error = await relay_reporter_update(case, interaction.user, note or "", attachments)
    if error:
        await interaction.followup.send(f"❌ Couldn't add that to the case: {error}", ephemeral=True)
    else:
        await interaction.followup.send(f"✅ Added to case #{case_id}. Thank you!", ephemeral=True)


async def handle_reporter_dm(message: discord.Message):
    cases = core.open_cases_for_reporter(message.author.id)
    ref, body = core.parse_case_ref(message.content or "")

    if not cases:
        last = _help_sent.get(message.author.id, 0.0)
        if time.time() - last > 3600:
            _help_sent[message.author.id] = time.time()
            await message.channel.send(HELP_TEXT)
        return

    if ref is not None:
        target = next((c for c in cases if c["id"] == ref), None)
        if target is None:
            await message.channel.send(f"I couldn't find an open case #{ref} filed by you.")
            return
    elif len(cases) == 1:
        target = cases[0]
    else:
        ids = ", ".join(f"#{c['id']}" for c in cases)
        await message.channel.send(
            f"You have several open reports ({ids}). Start your message with the case number, "
            f"for example `#{cases[0]['id']} here is more info`."
        )
        return

    if not body and not message.attachments:
        await message.channel.send("Send some text or screenshots and I'll add them to the case.")
        return

    error = await relay_reporter_update(target, message.author, body, list(message.attachments))
    try:
        await message.add_reaction("✅" if error is None else "⚠️")
    except discord.HTTPException:
        pass
    if error:
        await message.channel.send(f"I couldn't add that to case #{target['id']}: {error}")


# ------------------------------------------------------------------------------
# 8. REVIEWER PANEL
# ------------------------------------------------------------------------------
PANEL_BUTTONS = {
    "info": ("Request more info", discord.ButtonStyle.primary, "💬"),
    "act": ("Take action", discord.ButtonStyle.danger, "🔨"),
    "dismiss": ("Not applicable", discord.ButtonStyle.secondary, "✖️"),
}


class CaseButton(
    discord.ui.DynamicItem[discord.ui.Button],
    template=r"cb:(?P<action>info|act|dismiss):(?P<case_id>\d+)",
):
    def __init__(self, action: str, case_id: int, *, disabled: bool = False):
        label, style, emoji = PANEL_BUTTONS[action]
        super().__init__(
            discord.ui.Button(
                label=label,
                style=style,
                emoji=emoji,
                custom_id=f"cb:{action}:{case_id}",
                disabled=disabled,
            )
        )
        self.action = action
        self.case_id = case_id

    @classmethod
    async def from_custom_id(cls, interaction: discord.Interaction, item: discord.ui.Button, match, /):
        return cls(match["action"], int(match["case_id"]))

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if not await user_is_reviewer(interaction.user):
            await interaction.response.send_message("❌ Only reviewers can use this panel.", ephemeral=True)
            return False
        return True

    async def callback(self, interaction: discord.Interaction):
        case = core.get_case(self.case_id)
        if case is None:
            await interaction.response.send_message("❌ This case no longer exists.", ephemeral=True)
            return
        if case["status"] == core.STATUS_CLOSED:
            await interaction.response.send_message("This case is already closed.", ephemeral=True)
            return
        if self.action == "info":
            await interaction.response.send_modal(InfoRequestModal(self.case_id))
        elif self.action == "dismiss":
            await interaction.response.send_modal(DismissModal(self.case_id))
        else:
            await interaction.response.send_message(
                "Choose what to do with this case:",
                view=ActionPickView(self.case_id, interaction.user.id),
                ephemeral=True,
            )


def build_panel_view(case_id: int, disabled: bool = False) -> discord.ui.View:
    view = discord.ui.View(timeout=None)
    for action in ("info", "act", "dismiss"):
        view.add_item(CaseButton(action, case_id, disabled=disabled))
    return view


class InfoRequestModal(discord.ui.Modal, title="Request more information"):
    def __init__(self, case_id: int):
        super().__init__()
        self.case_id = case_id
        self.question = discord.ui.TextInput(
            label="What do you need from the reporter?",
            style=discord.TextStyle.paragraph,
            required=True,
            max_length=1000,
        )
        self.add_item(self.question)

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        case = core.get_case(self.case_id)
        if case is None or case["status"] == core.STATUS_CLOSED:
            await interaction.followup.send("This case is already closed.", ephemeral=True)
            return
        question = self.question.value.strip()

        embed = discord.Embed(
            title=f"Case #{case['id']} — more information requested",
            description=question,
            color=0x3498DB,
        )
        embed.add_field(
            name="How to reply",
            value=(
                f"Reply here starting with `#{case['id']}` (attach screenshots if you have them), "
                f"or use `/report-update case_id:{case['id']}`."
            ),
            inline=False,
        )
        dm_error = await dm_user(case["reporter_id"], embed=embed)

        core.update_case(case["id"], status=core.STATUS_NEEDS_INFO)
        core.add_event(case["id"], interaction.user.id, "info_requested", question)

        thread = await get_case_thread(case)
        if thread is not None:
            note = discord.Embed(
                title="💬 More information requested",
                description=core.clip(question, 3500),
                color=0x3498DB,
            )
            note.add_field(name="Asked by", value=interaction.user.mention, inline=True)
            note.add_field(
                name="Reporter DM",
                value="✅ Delivered" if dm_error is None else f"❌ {dm_error}",
                inline=True,
            )
            try:
                await thread.send(embed=note, allowed_mentions=NO_MENTIONS)
            except discord.HTTPException as exc:
                print(f"⚠️ Could not log info request on case #{case['id']}: {exc}")
        await refresh_case_ui(case["id"])

        if dm_error:
            await interaction.followup.send(
                f"⚠️ I couldn't DM the reporter ({dm_error}). The case is marked waiting, "
                "and they can still answer with `/report-update`.",
                ephemeral=True,
            )
        else:
            await interaction.followup.send("✅ Question sent to the reporter.", ephemeral=True)

    async def on_error(self, interaction: discord.Interaction, error: Exception):
        traceback.print_exception(type(error), error, error.__traceback__)
        await reply(interaction, "❌ Something went wrong.")


class DismissModal(discord.ui.Modal, title="Close as not applicable"):
    def __init__(self, case_id: int):
        super().__init__()
        self.case_id = case_id
        self.reason = discord.ui.TextInput(
            label="Reason (internal, kept in the case file)",
            style=discord.TextStyle.paragraph,
            required=True,
            max_length=900,
        )
        self.note = discord.ui.TextInput(
            label="Note to reporter (optional)",
            style=discord.TextStyle.paragraph,
            required=False,
            max_length=500,
        )
        self.add_item(self.reason)
        self.add_item(self.note)

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        if self.case_id in INFLIGHT:
            await interaction.followup.send("Someone is already deciding this case.", ephemeral=True)
            return
        INFLIGHT.add(self.case_id)
        try:
            case = core.get_case(self.case_id)
            if case is None or case["status"] == core.STATUS_CLOSED:
                await interaction.followup.send("This case is already closed.", ephemeral=True)
                return
            reason = self.reason.value.strip()
            core.update_case(
                case["id"],
                status=core.STATUS_CLOSED,
                decision=core.DECISION_DISMISSED,
                decision_reason=reason,
                decided_by=interaction.user.id,
                decided_at=int(time.time()),
            )
            core.add_event(case["id"], interaction.user.id, "dismissed", reason)

            thread = await get_case_thread(case)
            if thread is not None:
                try:
                    await thread.send(
                        embed=discord.Embed(
                            title="✖️ Closed as not applicable",
                            description=f"By {interaction.user.mention}\nReason: {core.clip(reason, 3500)}",
                            color=0x95A5A6,
                        ),
                        allowed_mentions=NO_MENTIONS,
                    )
                except discord.HTTPException as exc:
                    print(f"⚠️ Could not log dismissal on case #{case['id']}: {exc}")
            await notify_reporter_outcome(case, self.note.value)
            await refresh_case_ui(case["id"])
            await interaction.followup.send(f"✅ Case #{case['id']} closed as not applicable.", ephemeral=True)
        finally:
            INFLIGHT.discard(self.case_id)

    async def on_error(self, interaction: discord.Interaction, error: Exception):
        INFLIGHT.discard(self.case_id)
        traceback.print_exception(type(error), error, error.__traceback__)
        await reply(interaction, "❌ Something went wrong.")


# ------------------------------------------------------------------------------
# 9. PUNISHMENT FLOW (pick → details → preview → confirm)
# ------------------------------------------------------------------------------
class DiscordActionIO:
    """Real Discord implementation of the actions that core.run_actions calls."""

    def guild(self) -> Optional[discord.Guild]:
        if ACTION_GUILD_ID:
            return bot.get_guild(ACTION_GUILD_ID)
        forum = bot.get_channel(REVIEW_FORUM_ID) if REVIEW_FORUM_ID else None
        return forum.guild if forum is not None else None

    def unavailable_reason(self, action: str) -> Optional[str]:
        if action == core.ACTION_BAN and self.guild() is None:
            return "Ban: I can't reach the CyberByte server (set CYBERBYTE_GUILD_ID)."
        if action == core.ACTION_PUBLIC:
            if PUBLIC_WARNING_CHANNEL_ID is None:
                return "Public warning: PUBLIC_WARNING_CHANNEL_ID isn't configured."
            if bot.get_channel(PUBLIC_WARNING_CHANNEL_ID) is None:
                return "Public warning: I can't see the warnings channel."
        return None

    async def is_protected(self, user_id: int) -> bool:
        if bot.user is not None and user_id == bot.user.id:
            return True
        try:
            return bool(await bot.is_owner(discord.Object(id=user_id)))
        except Exception:
            return False

    async def dm_suspect(self, user_id: int, text: str, case_id: int) -> str:
        embed = discord.Embed(
            title="Notice from CyberByte",
            description=core.clip(text, 4000),
            color=0xE67E22,
        )
        error = await dm_user(user_id, embed=embed)
        if error:
            raise core.ActionError(f"Couldn't DM them: {error}")
        return "Warning delivered by DM."

    async def post_public(self, text: str, case_id: int) -> str:
        channel = bot.get_channel(PUBLIC_WARNING_CHANNEL_ID)
        if channel is None:
            raise core.ActionError("Warnings channel not found.")
        embed = discord.Embed(description=core.clip(text, 4000), color=0xFF0033, timestamp=now())
        embed.set_footer(text=f"CyberBot • Case #{case_id}")
        try:
            await channel.send(embed=embed, allowed_mentions=NO_MENTIONS)
        except discord.Forbidden:
            raise core.ActionError("I can't post in the warnings channel.")
        except discord.HTTPException as exc:
            raise core.ActionError(f"Discord error {exc.status} while posting.")
        return f"Posted in {channel.mention}."

    async def blacklist(self, user_id: int, reason: str, case_id: int) -> str:
        added = core.blacklist_add(user_id, reason, case_id)
        return "Added to the scammer database." if added else "Already on the blacklist."

    async def ban(self, user_id: int, reason: str) -> str:
        guild = self.guild()
        if guild is None:
            raise core.ActionError("I can't reach the CyberByte server.")
        try:
            await guild.ban(discord.Object(id=user_id), reason=reason, delete_message_seconds=0)
        except discord.Forbidden:
            raise core.ActionError("I lack Ban Members, or their role is above mine.")
        except discord.NotFound:
            raise core.ActionError("Discord doesn't know that user ID.")
        except discord.HTTPException as exc:
            raise core.ActionError(f"Discord error {exc.status} while banning.")
        return f"Banned from {guild.name}."


ACTION_OPTIONS = [
    discord.SelectOption(label="Blacklist", value=core.ACTION_BLACKLIST, description="Add to the scammer database", emoji="📛"),
    discord.SelectOption(label="Ban", value=core.ACTION_BAN, description="Ban from CyberByte", emoji="🔨"),
    discord.SelectOption(label="Public warning", value=core.ACTION_PUBLIC, description="Post a warning in the warnings channel", emoji="📢"),
    discord.SelectOption(label="DM warning", value=core.ACTION_DM, description="Send them a DM from the bot", emoji="✉️"),
]


class ActionPickView(discord.ui.View):
    def __init__(self, case_id: int, reviewer_id: int):
        super().__init__(timeout=300)
        self.case_id = case_id
        self.reviewer_id = reviewer_id
        self.selected: list = []

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.reviewer_id:
            await interaction.response.send_message("This menu belongs to another reviewer.", ephemeral=True)
            return False
        return True

    @discord.ui.select(placeholder="Choose one or more actions", min_values=1, max_values=4, options=ACTION_OPTIONS)
    async def pick(self, interaction: discord.Interaction, select: discord.ui.Select):
        self.selected = list(select.values)
        await interaction.response.defer()

    @discord.ui.button(label="Continue", style=discord.ButtonStyle.success)
    async def proceed(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not self.selected:
            await interaction.response.send_message("Pick at least one action first.", ephemeral=True)
            return
        await interaction.response.send_modal(ActionDetailsModal(self.case_id, self.selected))


class ActionDetailsModal(discord.ui.Modal, title="Action details"):
    def __init__(self, case_id: int, actions: list):
        super().__init__()
        self.case_id = case_id
        self.actions = actions
        self.reason = discord.ui.TextInput(
            label="Reason (internal, kept in the case file)",
            style=discord.TextStyle.paragraph,
            required=True,
            max_length=900,
        )
        self.add_item(self.reason)
        self.dm_text = None
        self.public_text = None
        if core.ACTION_DM in actions:
            self.dm_text = discord.ui.TextInput(
                label="DM text (blank = default message)",
                style=discord.TextStyle.paragraph,
                required=False,
                max_length=1500,
            )
            self.add_item(self.dm_text)
        if core.ACTION_PUBLIC in actions:
            self.public_text = discord.ui.TextInput(
                label="Public warning text (blank = default)",
                style=discord.TextStyle.paragraph,
                required=False,
                max_length=1500,
            )
            self.add_item(self.public_text)
        self.note = discord.ui.TextInput(
            label="Note to reporter (optional)",
            style=discord.TextStyle.paragraph,
            required=False,
            max_length=500,
        )
        self.add_item(self.note)

    async def on_submit(self, interaction: discord.Interaction):
        case = core.get_case(self.case_id)
        if case is None or case["status"] == core.STATUS_CLOSED:
            await interaction.response.send_message("This case is already closed.", ephemeral=True)
            return
        actions_io = DiscordActionIO()
        problems = [p for p in (actions_io.unavailable_reason(a) for a in self.actions) if p]
        if problems:
            await interaction.response.send_message(
                "❌ Can't run that yet:\n" + "\n".join(f"• {p}" for p in problems), ephemeral=True
            )
            return

        suspect_label = case["suspect_name"] or "this user"
        dm_text = (self.dm_text.value.strip() if self.dm_text else "") or core.default_dm_text(
            case["id"], APPEAL_TEXT
        )
        public_text = (self.public_text.value.strip() if self.public_text else "") or core.default_public_text(
            case["id"], suspect_label, case["suspect_id"]
        )
        reason = self.reason.value.strip()
        note = self.note.value.strip()

        guild = actions_io.guild()
        plan = []
        for action in core.ACTION_ORDER:
            if action in self.actions:
                label = core.ACTION_LABELS[action]
                if action == core.ACTION_BAN and guild is not None:
                    label += f" from {guild.name}"
                plan.append(f"• {label}")
        embed = discord.Embed(
            title=f"Confirm actions for case #{case['id']}",
            description=(
                f"Target: **{suspect_label}** (`{case['suspect_id']}`)\n"
                "Nothing runs until you press **Confirm and run**."
            ),
            color=0xE67E22,
        )
        embed.add_field(name="Will run, in this order", value="\n".join(plan), inline=False)
        if core.ACTION_DM in self.actions:
            embed.add_field(name="DM text", value=core.clip(dm_text, 1000), inline=False)
        if core.ACTION_PUBLIC in self.actions:
            embed.add_field(name="Public warning text", value=core.clip(public_text, 1000), inline=False)
        embed.add_field(name="Reason (internal)", value=core.clip(reason, 1000), inline=False)

        view = ConfirmActionView(
            reviewer_id=interaction.user.id,
            case_id=case["id"],
            actions=list(self.actions),
            reason=reason,
            dm_text=dm_text,
            public_text=public_text,
            reporter_note=note,
        )
        await interaction.response.send_message(embed=embed, view=view, ephemeral=True)

    async def on_error(self, interaction: discord.Interaction, error: Exception):
        traceback.print_exception(type(error), error, error.__traceback__)
        await reply(interaction, "❌ Something went wrong.")


class ConfirmActionView(discord.ui.View):
    def __init__(self, *, reviewer_id, case_id, actions, reason, dm_text, public_text, reporter_note):
        super().__init__(timeout=300)
        self.reviewer_id = reviewer_id
        self.case_id = case_id
        self.actions = actions
        self.reason = reason
        self.dm_text = dm_text
        self.public_text = public_text
        self.reporter_note = reporter_note

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.reviewer_id:
            await interaction.response.send_message("This confirmation belongs to another reviewer.", ephemeral=True)
            return False
        return True

    @discord.ui.button(label="Confirm and run", style=discord.ButtonStyle.danger, emoji="✅")
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        if self.case_id in INFLIGHT:
            await interaction.response.send_message("Someone is already deciding this case.", ephemeral=True)
            return
        INFLIGHT.add(self.case_id)
        try:
            await interaction.response.edit_message(content="⏳ Running…", embed=None, view=None)
            case = core.get_case(self.case_id)
            if case is None or case["status"] == core.STATUS_CLOSED:
                await interaction.edit_original_response(content="This case is already closed.")
                return

            results = await core.run_actions(
                DiscordActionIO(), case, self.actions, self.reason, self.dm_text, self.public_text
            )
            report_text = core.describe_results(results)
            succeeded = [r.action for r in results if r.ok]

            core.add_event(case["id"], interaction.user.id, "actions_run", report_text)
            thread = await get_case_thread(case)
            if thread is not None:
                embed = discord.Embed(
                    title="🔨 Actions run" if succeeded else "⚠️ Actions attempted, none succeeded",
                    description=core.clip(report_text, 3500),
                    color=0x2ECC71 if succeeded else 0xE74C3C,
                )
                embed.add_field(name="Decided by", value=interaction.user.mention, inline=True)
                embed.add_field(name="Reason (internal)", value=core.clip(self.reason, 1000), inline=False)
                try:
                    await thread.send(embed=embed, allowed_mentions=NO_MENTIONS)
                except discord.HTTPException as exc:
                    print(f"⚠️ Could not log actions on case #{case['id']}: {exc}")

            if succeeded:
                core.update_case(
                    case["id"],
                    status=core.STATUS_CLOSED,
                    decision="action: " + ", ".join(core.ACTION_LABELS[a].lower() for a in succeeded),
                    decision_reason=self.reason,
                    decided_by=interaction.user.id,
                    decided_at=int(time.time()),
                )
                await notify_reporter_outcome(case, self.reporter_note)
            await refresh_case_ui(case["id"])

            if succeeded and len(succeeded) == len(results):
                headline = "✅ Done."
            elif succeeded:
                headline = "⚠️ Partly done. The case is closed, so follow up on the failures manually."
            else:
                headline = "❌ Nothing succeeded. The case is still open."
            await interaction.edit_original_response(content=f"{headline}\n{report_text}")
        finally:
            INFLIGHT.discard(self.case_id)

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.edit_message(content="Cancelled. Nothing was changed.", embed=None, view=None)


# ------------------------------------------------------------------------------
# 10. /cases LOOKUP
# ------------------------------------------------------------------------------
@bot.tree.command(name="cases", description="[Reviewer] Show the case history for a user ID.")
@app_commands.describe(user_id="Discord user ID or mention")
@app_commands.allowed_installs(guilds=True, users=False)
@app_commands.guild_only()
@reviewer_only()
async def cases_cmd(interaction: discord.Interaction, user_id: str):
    uid = core.extract_user_id(user_id)
    if uid is None:
        await interaction.response.send_message("❌ That doesn't look like a user ID.", ephemeral=True)
        return
    rows = core.cases_for_suspect(uid, limit=15)
    lines = []
    forum = await get_review_forum()
    for row in rows:
        label = STATUS_META[status_key(row)][0]
        if row["thread_id"] and forum is not None:
            # a normal channel mention only works inside the forum's own server
            link = f" — [open post](https://discord.com/channels/{forum.guild.id}/{row['thread_id']})"
        else:
            link = ""
        detail = f" ({row['decision']})" if row["status"] == core.STATUS_CLOSED and row["decision"] else ""
        lines.append(f"**#{row['id']}** — {label}{detail}{link}")
    embed = discord.Embed(
        title=f"Cases against {uid}",
        description="\n".join(lines) if lines else "No cases on file.",
        color=0x3498DB,
    )
    embed.add_field(
        name="Blacklist",
        value="⛔ Listed" if core.is_blacklisted(uid) else "Not listed",
        inline=True,
    )
    await interaction.response.send_message(embed=embed, ephemeral=True)


# ------------------------------------------------------------------------------
# 11. READY EVENT, ERROR HANDLER, STARTUP CHECKS
# ------------------------------------------------------------------------------
async def startup_checks():
    forum = await get_review_forum()
    if forum is None:
        print(
            f"⚠️ Review forum ({REVIEW_FORUM_ID or 'REVIEW_FORUM_ID is not set'}) not found "
            "or not a forum channel. Reports can't be filed."
        )
    else:
        perms = forum.permissions_for(forum.guild.me)
        needed = [
            "view_channel", "send_messages", "send_messages_in_threads",
            "embed_links", "attach_files", "read_message_history",
        ]
        missing = [name for name in needed if not getattr(perms, name)]
        if missing:
            print(f"⚠️ I'm missing permissions in #{forum.name}: {', '.join(missing)}")
        else:
            print(f"📥 Review forum ready: #{forum.name}")
    guild = DiscordActionIO().guild()
    if guild is None:
        print("⚠️ Ban action unavailable: can't determine the CyberByte server (set CYBERBYTE_GUILD_ID).")
    elif not guild.me.guild_permissions.ban_members:
        print(f"⚠️ I don't have Ban Members in {guild.name}; the ban action will fail.")
    if PUBLIC_WARNING_CHANNEL_ID is None:
        print("ℹ️ PUBLIC_WARNING_CHANNEL_ID not set: the public warning action is disabled.")
    if REVIEWER_ROLE_ID is None:
        print("ℹ️ REVIEWER_ROLE_ID not set: only the bot owner can review cases.")


@bot.event
async def on_ready():
    global _startup_checked
    print(f"✅ Logged in as: {bot.user.name} (ID: {bot.user.id})")
    if not _startup_checked:
        _startup_checked = True
        await startup_checks()


@bot.tree.error
async def on_tree_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    command = interaction.command
    if command is not None and getattr(command, "on_error", None) is not None:
        return  # the command has its own error handler
    if isinstance(error, app_commands.MissingPermissions):
        await reply(interaction, "❌ You don't have the permissions to use this command.")
    elif isinstance(error, app_commands.CheckFailure):
        await reply(interaction, "❌ You aren't allowed to use this command.")
    else:
        traceback.print_exception(type(error), error, error.__traceback__)
        await reply(interaction, "❌ Something went wrong running that command.")


# ------------------------------------------------------------------------------
# 12. ORIGINAL SERVER COMMANDS (setup, alert, scammer database, scan, status)
# ------------------------------------------------------------------------------
class SetupView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=180)

    @discord.ui.button(label="Configure Security Alerts", style=discord.ButtonStyle.primary, emoji="📢")
    async def setup_alerts_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        guild = interaction.guild
        existing = discord.utils.get(guild.text_channels, name=ALERT_CHANNEL_NAME)
        if existing:
            await interaction.response.send_message(
                f"⚠️ The security alerts feed is already active in {existing.mention}.", ephemeral=True)
            return
        try:
            channel = await guild.create_text_channel(
                name=ALERT_CHANNEL_NAME,
                topic="CyberBot Official Threat Intelligence & Security Alerts Feed",
            )
            embed = discord.Embed(
                title="🛡️ CyberBot Security Alerts Feed",
                description="This channel receives real-time scam warnings and global threat advisories.",
                color=0x3498DB,
                timestamp=now(),
            )
            embed.add_field(name="Status", value="🟢 Active & Monitoring", inline=True)
            embed.set_footer(text="CyberBot Threat Intelligence")
            welcome = await channel.send(embed=embed)
            try:
                await welcome.pin()
            except Exception:
                pass
            await interaction.response.send_message(
                f"✅ Successfully initialized the security alerts feed in {channel.mention}!", ephemeral=True)
        except discord.Forbidden:
            await interaction.response.send_message(
                "❌ **Permission Error:** I lack the `Manage Channels` permission.", ephemeral=True)
        except Exception as exc:
            await interaction.response.send_message(f"❌ An unexpected error occurred: {exc}", ephemeral=True)

    @discord.ui.button(label="Configure Honeypot Trap", style=discord.ButtonStyle.danger, emoji="🪤")
    async def setup_honeypot_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        guild = interaction.guild
        existing = discord.utils.get(guild.text_channels, name=HONEYPOT_CHANNEL_NAME)
        if existing:
            await interaction.response.send_message(
                f"⚠️ The honeypot trap channel is already active in {existing.mention}.", ephemeral=True)
            return
        try:
            overwrites = {
                guild.default_role: discord.PermissionOverwrite(read_messages=True, send_messages=True),
                guild.me: discord.PermissionOverwrite(
                    read_messages=True, send_messages=True, manage_messages=True, embed_links=True),
            }
            channel = await guild.create_text_channel(
                name=HONEYPOT_CHANNEL_NAME,
                overwrites=overwrites,
                topic="🚨 SECURITY HONEYPOT: Any message sent here will automatically trigger an instant kick.",
            )
            embed = discord.Embed(
                title="⚠️ Active Security Honeypot",
                description=(
                    "**NOTICE:** This channel is an automated security trap.\n\n"
                    "• **Human Members:** Do **NOT** send messages here!\n"
                    "• **Automated Bots & Violators:** Any message posted here will be "
                    "**instantly deleted** and the sender will be **kicked**."
                ),
                color=0xFF0033,
                timestamp=now(),
            )
            embed.set_footer(text="CyberBot Automated Proactive Defense")
            await channel.send(embed=embed)
            await interaction.response.send_message(
                f"✅ Successfully deployed the security honeypot trap in {channel.mention}!", ephemeral=True)
        except discord.Forbidden:
            await interaction.response.send_message(
                "❌ **Permission Error:** I lack `Manage Channels` permissions.", ephemeral=True)
        except Exception as exc:
            await interaction.response.send_message(f"❌ An unexpected error occurred: {exc}", ephemeral=True)


@bot.tree.command(name="setup", description="[Admin Only] Open the CyberBot module control panel.")
@app_commands.allowed_installs(guilds=True, users=False)
@app_commands.guild_only()
@app_commands.checks.has_permissions(manage_channels=True)
async def setup(interaction: discord.Interaction):
    embed = discord.Embed(
        title="⚙️ CyberBot Control Panel — Module Setup",
        description=(
            "Configure CyberBot security modules for your server by clicking the options below:\n\n"
            "• 📢 **Security Alerts Feed:** Deploys `#cyberbot-alerts` for real-time threat advisories.\n"
            "• 🪤 **Honeypot Trap:** Deploys `#security-honeypot` to automatically catch and eject spambots."
        ),
        color=0x2ECC71,
    )
    embed.set_footer(text="Select a module button below to configure your server.")
    await interaction.response.send_message(embed=embed, view=SetupView(), ephemeral=True)


@bot.tree.command(
    name="alert",
    description="[Owner Only] Broadcast a global security alert embed to all connected servers.",
)
@app_commands.describe(
    title="The title of the security warning",
    message="The full details and prevention instructions.",
)
@app_commands.allowed_installs(guilds=True, users=False)
@is_bot_owner()
async def alert(interaction: discord.Interaction, title: str, message: str):
    await interaction.response.defer(thinking=True, ephemeral=True)
    embed = discord.Embed(
        title=f"🚨 {title}"[:256],
        description=message[:4000],
        color=0xFF0033,
        timestamp=now(),
    )
    embed.add_field(name="⚠️ Priority Level", value="HIGH — Security Threat", inline=True)
    embed.add_field(name="🛡️ Action Required", value="Verify links & inform community.", inline=True)
    embed.set_footer(text="CyberBot Official Threat Intelligence")

    success_count = 0
    fail_count = 0
    for guild in bot.guilds:
        channel = discord.utils.get(guild.text_channels, name=ALERT_CHANNEL_NAME)
        if channel:
            try:
                await channel.send(embed=embed)
                success_count += 1
                await asyncio.sleep(0.5)
            except Exception as exc:
                fail_count += 1
                print(f"Failed to deliver alert to '{guild.name}': {exc}")
    await interaction.followup.send(
        f"✅ **Broadcast Completed!**\n"
        f"• Delivered to: **{success_count}** server(s)\n"
        f"• Failed/Skipped: **{fail_count}** server(s)",
        ephemeral=True,
    )


@bot.tree.command(
    name="add-scammer",
    description="[Owner Only] Add a verified scammer to the global threat database.",
)
@app_commands.describe(
    user_id="The Discord User ID of the scammer",
    reason="The reason or proof summary",
)
@app_commands.allowed_installs(guilds=True, users=False)
@is_bot_owner()
async def add_scammer(interaction: discord.Interaction, user_id: str, reason: str):
    uid = core.extract_user_id(user_id)
    if uid is None:
        await interaction.response.send_message("❌ User ID must be numeric.", ephemeral=True)
        return
    if not core.blacklist_add(uid, reason):
        await interaction.response.send_message(
            f"❌ User ID {uid} is already logged in the database.", ephemeral=True)
        return
    await interaction.response.send_message(
        f"✅ Added threat actor: User ID {uid} — Reason: {reason}", ephemeral=True)


@bot.tree.command(
    name="scan-members",
    description="[Admin Only] Audit current server members against the global scammer database.",
)
@app_commands.allowed_installs(guilds=True, users=False)
@app_commands.guild_only()
@app_commands.checks.has_permissions(administrator=True)
async def scan_members(interaction: discord.Interaction):
    await interaction.response.defer(thinking=True, ephemeral=True)
    data = core.load_scammers()
    scammer_ids = {str(e.get("user_id")): e.get("reason", "") for e in data["scammers"]}
    if not scammer_ids:
        await interaction.followup.send(
            "✅ Audit Complete: The global scammer database is currently empty.", ephemeral=True)
        return

    guild = interaction.guild
    if not guild.chunked:
        await guild.chunk()  # make sure the full member list is cached

    found = []
    for member in guild.members:
        sid = str(member.id)
        if sid in scammer_ids:
            found.append(f"• {member} ({sid}) — Reason: {scammer_ids[sid]}")

    if found:
        embed = discord.Embed(
            title="🚨 Security Alert: Threat Actors Found in Server!",
            description=core.clip("\n".join(found), 4000),
            color=0xFF0033,
            timestamp=now(),
        )
        embed.set_footer(text="CyberBot Security Audit")
        await interaction.followup.send(embed=embed, ephemeral=True)
    else:
        await interaction.followup.send(
            "✅ Audit Complete: No known threat actors were detected among current server members.",
            ephemeral=True)


@bot.tree.command(
    name="security-status",
    description="Display the real-time security status and active modules for this server.",
)
@app_commands.allowed_installs(guilds=True, users=False)
@app_commands.guild_only()
async def security_status(interaction: discord.Interaction):
    guild = interaction.guild
    alerts_channel = discord.utils.get(guild.text_channels, name=ALERT_CHANNEL_NAME)
    honeypot_channel = discord.utils.get(guild.text_channels, name=HONEYPOT_CHANNEL_NAME)
    forum = await get_review_forum()

    alerts_status = f"🟢 Active ({alerts_channel.mention})" if alerts_channel else "🔴 Not Configured"
    honeypot_status = f"🟢 Active ({honeypot_channel.mention})" if honeypot_channel else "🔴 Not Configured"
    if forum is None:
        intake_status = "🔴 Review forum unreachable"
    elif forum.guild.id == guild.id:
        intake_status = f"🟢 Active ({forum.mention})"
    else:
        intake_status = "🟢 Active (review forum is in another server)"

    embed = discord.Embed(
        title=f"🛡️ CyberBot Security Dashboard — {guild.name}",
        description="Real-time operational status of CyberBot security modules on this server.",
        color=0x2ECC71,
        timestamp=now(),
    )
    embed.add_field(name="📢 Threat Alerts Feed", value=alerts_status, inline=True)
    embed.add_field(name="🪤 Honeypot Trap", value=honeypot_status, inline=True)
    embed.add_field(name="📥 Report Intake", value=intake_status, inline=True)
    embed.add_field(name="⚡ Core Specs", value=f"• Engine: discord.py {discord.__version__}", inline=False)

    if not alerts_channel or not honeypot_channel:
        embed.set_footer(text="💡 Tip: Run /setup to quickly deploy missing security modules!")
    else:
        embed.set_footer(text="CyberBot Threat Intelligence • All systems operational")
    await interaction.response.send_message(embed=embed, ephemeral=True)


# ------------------------------------------------------------------------------
# 13. MESSAGE EVENTS (reporter DMs + honeypot trap)
# ------------------------------------------------------------------------------
@bot.event
async def on_message(message: discord.Message):
    if message.author.bot:
        return

    if message.guild is None:
        try:
            await handle_reporter_dm(message)
        except Exception:
            traceback.print_exc()
        return

    if message.channel.name == HONEYPOT_CHANNEL_NAME:
        try:
            await message.delete()
        except Exception:
            pass

        is_server_owner = message.guild.owner_id == message.author.id
        bot_member = message.guild.me
        author_top = getattr(message.author, "top_role", None)
        is_higher_role = author_top is not None and author_top >= bot_member.top_role

        if is_server_owner or is_higher_role:
            warning_embed = discord.Embed(
                title="⚠️ Honeypot Triggered — Action Restricted",
                description=(
                    f"User: {message.author.mention} ({message.author.id})\n"
                    "❌ Unable to kick user: their role is higher than or equal to the bot's, "
                    "or they are the server owner."
                ),
                color=0xF1C40F,
                timestamp=now(),
            )
            await message.channel.send(embed=warning_embed, delete_after=12)
        else:
            try:
                await message.guild.kick(
                    message.author, reason="[CyberBot Honeypot] Triggered security trap channel.")
                success_embed = discord.Embed(
                    title="🚨 Honeypot Trap Triggered",
                    description=(
                        f"Ejected User: {message.author} ({message.author.id})\n"
                        "🛡️ The user triggered the automated trap and has been kicked from the server."
                    ),
                    color=0xFF0033,
                    timestamp=now(),
                )
                await message.channel.send(embed=success_embed, delete_after=8)
            except discord.Forbidden:
                err_embed = discord.Embed(
                    title="⚠️ Honeypot Error",
                    description="❌ Permission Error: I lack the Kick Members permission.",
                    color=0xFF0033,
                )
                await message.channel.send(embed=err_embed, delete_after=10)
            except Exception as exc:
                print(f"❌ Error handling honeypot execution: {exc}")
        return

    await bot.process_commands(message)


# ------------------------------------------------------------------------------
# 14. BOT EXECUTION
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    if not TOKEN:
        print("❌ ERROR: DISCORD_TOKEN is missing!")
    else:
        bot.run(TOKEN)
