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
# Optional: replaces the default appeal instructions in the DM people get. Leave it unset to
# use the built-in text, which points at the Appeal button.
APPEAL_TEXT = os.getenv("APPEAL_TEXT") or None
BOT_VERSION = "1.1.0"

ALERT_CHANNEL_NAME = "cyberbot-alerts"
HONEYPOT_CHANNEL_NAME = core.DEFAULT_HONEYPOT_NAME

intents = discord.Intents.default()
intents.guilds = True
intents.guild_messages = True
intents.message_content = True  # privileged: enable in the Developer Portal
intents.members = True          # privileged: enable in the Developer Portal

NO_MENTIONS = discord.AllowedMentions.none()
HELP_TEXT = (
    "👋 I'm CyberBot. To report a scammer or cyberbullying, right-click (or long-press) one of their "
    "messages, choose **Apps → Report to CyberBot**, and I'll open a case and message you here. "
    "If I sent you a notice and you think it was a mistake, press the **Appeal** button on it."
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
        self.add_dynamic_items(CaseButton, AppealButton, AppealReviewButton)
        load_honeypot_cache()
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
    "appeal": ("Action taken — appeal pending", 0x9B59B6),
    "overturned": ("Closed — overturned on appeal", 0x1ABC9C),
}
# Forum tags with these names (case-insensitive) are applied automatically if they exist.
STATUS_TAG_NAMES = {
    "open": "open",
    "needs_info": "needs info",
    "dismissed": "dismissed",
    "actioned": "actioned",
    "appeal": "appeal",
    "overturned": "overturned",
}
TYPE_TAG_NAMES = {
    core.CASE_SCAM: "scam",
    core.CASE_BULLYING: "cyberbullying",
    core.CASE_OTHER: "other",
}


def status_key(case) -> str:
    if case["status"] != core.STATUS_CLOSED:
        return case["status"]
    if case["decision"] == core.DECISION_DISMISSED:
        return "dismissed"
    if case["decision"] == core.DECISION_OVERTURNED:
        return "overturned"
    if core.decision_is_action(case["decision"]):
        appeal = core.appeal_for_case(case["id"])
        if appeal is not None and appeal["status"] == core.APPEAL_OPEN:
            return "appeal"
    return "actioned"


def _tags_named(forum: discord.ForumChannel, names) -> list:
    wanted = {n.strip().lower() for n in names}
    return [t for t in forum.available_tags if t.name.strip().lower() in wanted]


def pick_tags(forum: discord.ForumChannel, case) -> list:
    tags = _tags_named(forum, [STATUS_TAG_NAMES[status_key(case)]])
    for tag in _tags_named(forum, [TYPE_TAG_NAMES.get(case["case_type"], "other")]):
        if tag not in tags:
            tags.append(tag)
    if not tags and forum.flags.require_tag and forum.available_tags:
        tags = [forum.available_tags[0]]  # the forum insists on a tag
    return tags[:5]


def post_url(thread_id) -> Optional[str]:
    """Link to a forum post. A plain channel mention only works inside the forum's own server."""
    forum = bot.get_channel(REVIEW_FORUM_ID)
    if forum is None or not thread_id:
        return None
    return f"https://discord.com/channels/{forum.guild.id}/{thread_id}"


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
    embed.add_field(name="Type", value=core.case_type_label(case["case_type"]), inline=True)
    embed.add_field(name="History", value=core.clip(history_text(case), 1000), inline=False)
    if case["status"] == core.STATUS_CLOSED and case["decided_at"]:
        decision = (
            f"**{core.decision_label(case['decision'])}**\n"
            f"By <@{case['decided_by']}> on <t:{case['decided_at']}:f>\n"
            f"Reason: {case['decision_reason'] or '—'}"
        )
        embed.add_field(name="Decision", value=core.clip(decision, 1000), inline=False)
    else:
        embed.description = "Review the evidence in this post, then use the buttons below."
    appeal = core.appeal_for_case(case["id"])
    if appeal is not None:
        state = {
            core.APPEAL_OPEN: "⏳ Pending review",
            core.APPEAL_UPHELD: "Rejected — the original decision stands",
            core.APPEAL_OVERTURNED: "Accepted — the action was lifted",
        }.get(appeal["status"], appeal["status"])
        text = f"{state}\nFiled <t:{appeal['created_at']}:f>"
        link = post_url(appeal["thread_id"])
        if link:
            text += f"\n[Open appeal post]({link})"
        embed.add_field(name="Appeal", value=text, inline=False)
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


def reporter_receipt_embed(case_id: int, case_type: str = core.DEFAULT_CASE_TYPE) -> discord.Embed:
    embed = discord.Embed(
        title=f"✅ Report received — case #{case_id}",
        description=(
            "A reviewer will look at it, usually within a day. If we need more information "
            "we'll message you here."
        ),
        color=0x2ECC71,
    )
    embed.add_field(name="Type", value=core.case_type_label(case_type), inline=True)
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
            "Your report, the reported message and anything you add are stored by CyberBot, "
            "shown to the review team and kept on file so the case can be looked at again later."
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
    case_type: str = core.DEFAULT_CASE_TYPE,
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
        case_type=case_type if case_type in core.CASE_TYPE_LABELS else core.DEFAULT_CASE_TYPE,
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
    dm_error = await dm_user(reporter.id, embed=reporter_receipt_embed(case_id, case["case_type"]))
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
    managed = set(STATUS_TAG_NAMES.values()) | set(TYPE_TAG_NAMES.values())
    keep = [t for t in thread.applied_tags if t.name.strip().lower() not in managed]
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
REPORT_TYPE_INFO = {
    core.CASE_SCAM: ("🎣", "Scam / fraud", "Explain what they did (scam, phishing, fake giveaway, impersonation...)."),
    core.CASE_BULLYING: ("🛑", "Cyberbullying / harassment", "Explain what they did (threats, harassment, targeting someone...)."),
    core.CASE_OTHER: ("📋", "Other", "Explain what happened and why it should be reviewed."),
}
TYPE_CHOICES = [app_commands.Choice(name=info[1], value=key) for key, info in REPORT_TYPE_INFO.items()]


class ReportModal(discord.ui.Modal):
    def __init__(self, case_type: str, anchor: Optional[discord.Message] = None, suspect=None):
        _emoji, label, hint = REPORT_TYPE_INFO[case_type]
        super().__init__(title=f"Report: {label}"[:45])
        self.case_type = case_type
        self.anchor = anchor
        self.suspect = suspect
        self.details = discord.ui.TextInput(
            label="What happened?",
            style=discord.TextStyle.paragraph,
            placeholder=hint[:100],
            required=True,
            max_length=1000,
        )
        self.context = discord.ui.TextInput(
            label="Paste the rest of the conversation",
            style=discord.TextStyle.paragraph,
            placeholder="Optional. Paste the conversation here (counts as unverified).",
            required=False,
            max_length=4000,
        )
        self.add_item(self.details)
        self.add_item(self.context)

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
            case_type=self.case_type,
        )
        if error:
            await interaction.followup.send(f"❌ {error}", ephemeral=True)
            return
        text = f"✅ Report submitted as **case #{case_id}** ({core.case_type_label(self.case_type)})."
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


class ReportTypeView(discord.ui.View):
    """Asks what kind of report this is, then opens the form."""

    def __init__(self, reporter_id: int, anchor: Optional[discord.Message] = None, suspect=None):
        super().__init__(timeout=300)
        self.reporter_id = reporter_id
        self.anchor = anchor
        self.suspect = suspect
        for case_type, (emoji, label, _hint) in REPORT_TYPE_INFO.items():
            button = discord.ui.Button(
                label=label,
                emoji=emoji,
                style=discord.ButtonStyle.danger if case_type == core.CASE_SCAM else discord.ButtonStyle.secondary,
            )
            button.callback = self._opener(case_type)
            self.add_item(button)

    def _opener(self, case_type: str):
        async def open_form(interaction: discord.Interaction):
            await interaction.response.send_modal(ReportModal(case_type, self.anchor, self.suspect))
        return open_form

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.reporter_id:
            await interaction.response.send_message("This menu belongs to someone else.", ephemeral=True)
            return False
        return True


ASK_TYPE_TEXT = "**What kind of report is this?** Pick one and I'll open the form."


@bot.tree.context_menu(name="Report to CyberBot")
@app_commands.allowed_installs(guilds=True, users=True)
@app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
async def report_message_menu(interaction: discord.Interaction, message: discord.Message):
    problem = check_report_allowed(interaction.user.id, message.author.id)
    if problem:
        await interaction.response.send_message(problem, ephemeral=True)
        return
    await interaction.response.send_message(
        ASK_TYPE_TEXT, view=ReportTypeView(interaction.user.id, anchor=message), ephemeral=True
    )


@bot.tree.context_menu(name="Report user to CyberBot")
@app_commands.allowed_installs(guilds=True, users=True)
@app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
async def report_user_menu(interaction: discord.Interaction, user: Union[discord.Member, discord.User]):
    problem = check_report_allowed(interaction.user.id, user.id)
    if problem:
        await interaction.response.send_message(problem, ephemeral=True)
        return
    await interaction.response.send_message(
        ASK_TYPE_TEXT, view=ReportTypeView(interaction.user.id, suspect=user), ephemeral=True
    )


@bot.tree.command(
    name="report",
    description="Report a scammer or cyberbullying. Tip: right-click a message → Apps → Report to CyberBot is easier.",
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
    report_type="What kind of report this is (default: scam)",
)
@app_commands.choices(report_type=TYPE_CHOICES)
async def report(
    interaction: discord.Interaction,
    suspect_id: str,
    evidence: app_commands.Range[str, 1, 1000],
    proof_1: discord.Attachment,
    proof_2: Optional[discord.Attachment] = None,
    proof_3: Optional[discord.Attachment] = None,
    proof_4: Optional[discord.Attachment] = None,
    report_type: str = core.CASE_SCAM,
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
        case_type=report_type,
    )
    if error:
        await interaction.followup.send(f"❌ {error}", ephemeral=True)
        return
    text = (
        f"✅ Report submitted as **case #{case_id}** ({core.case_type_label(report_type)}, "
        "screenshots only, so it is marked unverified)."
    )
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
    appeal = core.parse_appeal_message(message.content or "")
    if appeal is not None:
        case_ref, statement = appeal
        if not statement:
            await message.channel.send(
                f"Add your explanation after the case number, for example "
                f"`appeal #{case_ref} I think this was a mistake because...`. "
                "You can also press the **Appeal** button on the notice I sent you."
            )
            return
        _ok, answer = await submit_appeal(message.author.id, case_ref, statement)
        await message.channel.send(answer)
        return

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
                view=ActionPickView(self.case_id, interaction.user.id, case["case_type"]),
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
def blacklist_case_id(user_id: int) -> Optional[int]:
    for entry in core.blacklist_entries():
        if entry["user_id"] == user_id:
            return entry["case_id"]
    return None


def autoban_guilds() -> list:
    """Servers that opted in to pre-banning and that the bot is still in."""
    guilds = []
    for guild_id in core.autoban_guild_ids():
        guild = bot.get_guild(guild_id)
        if guild is not None:
            guilds.append(guild)
    return guilds


async def preban_user(guild: discord.Guild, user_id: int, case_id: Optional[int]) -> Optional[str]:
    """Bans a blacklisted ID in one server. Returns None on success, otherwise a short problem."""
    if guild.owner_id == user_id or (bot.user is not None and user_id == bot.user.id):
        return "protected account"
    try:
        # The reason is generic on purpose: other servers never see the internal reviewer reason.
        await guild.ban(discord.Object(id=user_id), reason=core.preban_reason(case_id), delete_message_seconds=0)
    except discord.Forbidden:
        return "I lack Ban Members or their role is above mine"
    except discord.NotFound:
        return "Discord doesn't know that user ID"
    except discord.HTTPException as exc:
        return f"Discord error {exc.status}"
    return None


async def preban_everywhere(user_id: int, case_id: Optional[int], skip_guild_id: Optional[int] = None) -> tuple:
    """Pre-bans a newly blacklisted ID in every opted-in server. Returns (banned, failed)."""
    done = failed = 0
    for guild in autoban_guilds():
        if guild.id == skip_guild_id:
            continue
        problem = await preban_user(guild, user_id, case_id)
        if problem:
            failed += 1
            print(f"⚠️ Pre-ban of {user_id} failed in {guild.name}: {problem}")
        else:
            done += 1
        await asyncio.sleep(0.3)
    return done, failed


def _is_cyberbot_ban(reason: Optional[str], case_id: Optional[int]) -> bool:
    """Only bans CyberBot placed for this case (or for a case-less blacklist entry) may be lifted."""
    if case_id is not None:
        return core.ban_is_ours(reason, case_id)
    return bool(reason) and reason.startswith("[CyberBot Blacklist]")


async def lift_cyberbot_bans(guilds, user_id: int, case_id: Optional[int], reason: str) -> tuple:
    """Unbans a user wherever CyberBot banned them for this case. Returns (lifted_names, problems)."""
    lifted, problems, seen = [], [], set()
    for guild in guilds:
        if guild is None or guild.id in seen:
            continue
        seen.add(guild.id)
        target = discord.Object(id=user_id)
        try:
            entry = await guild.fetch_ban(target)
        except discord.NotFound:
            continue  # not banned here (or already lifted)
        except discord.Forbidden:
            problems.append(f"{guild.name}: I can't view bans there")
            continue
        except discord.HTTPException as exc:
            problems.append(f"{guild.name}: Discord error {exc.status}")
            continue
        if not _is_cyberbot_ban(entry.reason, case_id):
            continue  # a ban someone placed by hand stays
        try:
            await guild.unban(target, reason=reason)
        except discord.Forbidden:
            problems.append(f"{guild.name}: I lack Ban Members")
        except discord.HTTPException as exc:
            problems.append(f"{guild.name}: Discord error {exc.status}")
        else:
            lifted.append(guild.name)
        await asyncio.sleep(0.3)
    return lifted, problems


class DiscordActionIO:
    """Real Discord implementation of the actions that core.run_actions / run_reversal call."""

    def __init__(self, case_id: Optional[int] = None, will_ban: bool = False):
        self.case_id = case_id
        self.will_ban = will_ban  # the main server gets a real ban, so don't pre-ban it a second time

    def guild(self) -> Optional[discord.Guild]:
        if ACTION_GUILD_ID:
            return bot.get_guild(ACTION_GUILD_ID)
        forum = bot.get_channel(REVIEW_FORUM_ID) if REVIEW_FORUM_ID else None
        return forum.guild if forum is not None else None

    def unavailable_reason(self, action: str, user_id: Optional[int] = None) -> Optional[str]:
        if action == core.ACTION_BAN:
            guild = self.guild()
            if guild is None:
                return "Ban: I can't reach the CyberByte server (set CYBERBYTE_GUILD_ID)."
            if not guild.me.guild_permissions.ban_members:
                return f"Ban: I don't have Ban Members in {guild.name}."
            if user_id is not None:
                member = guild.get_member(user_id)
                if member is not None and (guild.owner_id == user_id or member.top_role >= guild.me.top_role):
                    return "Ban: their role is higher than or equal to mine, or they own the server."
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
            title=f"Notice from {core.COMMUNITY_NAME}",
            description=core.clip(text, 4000),
            color=0xE67E22,
        )
        error = await dm_user(user_id, embed=embed, view=build_appeal_view(case_id))
        if error:
            raise core.ActionError(
                f"Couldn't DM them: {error}. They can still appeal with /appeal case_id:{case_id}."
            )
        return "Notice delivered by DM, with an Appeal button."

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

    async def blacklist(self, user_id: int, reason: str, case_id: int, case_type: str) -> str:
        added = core.blacklist_add(user_id, reason, case_id, case_type)
        if not added:
            return "Already on the blacklist."
        text = "Added to the scammer database."
        main = self.guild()
        skip = main.id if (self.will_ban and main is not None) else None
        done, failed = await preban_everywhere(user_id, case_id, skip_guild_id=skip)
        if done or failed:
            text += f" Pre-banned in {done} opted-in server(s)"
            text += f" ({failed} failed)." if failed else "."
        return text

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

    async def unban(self, user_id: int, reason: str) -> str:
        guilds = [self.guild()] + autoban_guilds()
        lifted, problems = await lift_cyberbot_bans(guilds, user_id, self.case_id, reason)
        if problems:
            done = ", ".join(lifted) if lifted else "nowhere"
            raise core.ActionError(f"Unbanned in: {done}. Problems: " + "; ".join(problems))
        if not lifted:
            return "No CyberBot ban for this case was found, so nothing was lifted (already unbanned, or banned by hand)."
        return "Unbanned in " + ", ".join(lifted) + "."

    async def unblacklist(self, user_id: int) -> str:
        return (
            "Removed from the scammer database."
            if core.blacklist_remove(user_id)
            else "Wasn't on the blacklist."
        )


ACTION_OPTION_LIST = {
    core.ACTION_BLACKLIST: discord.SelectOption(
        label="Blacklist", value=core.ACTION_BLACKLIST,
        description="Add to the scammer database (they get a DM)", emoji="📛"),
    core.ACTION_BAN: discord.SelectOption(
        label="Ban", value=core.ACTION_BAN, description="Ban from CyberByte (they get a DM first)", emoji="🔨"),
    core.ACTION_PUBLIC: discord.SelectOption(
        label="Public warning", value=core.ACTION_PUBLIC,
        description="Post a warning in the warnings channel (scams only)", emoji="📢"),
    core.ACTION_DM: discord.SelectOption(
        label="DM warning", value=core.ACTION_DM, description="Send them a DM from the bot", emoji="✉️"),
}


def action_options(case_type: Optional[str]) -> list:
    """Public warnings name someone in public, so they're only offered for scam cases."""
    return [
        option for key, option in ACTION_OPTION_LIST.items()
        if key != core.ACTION_PUBLIC or core.public_warning_allowed(case_type)
    ]


class ActionPickView(discord.ui.View):
    def __init__(self, case_id: int, reviewer_id: int, case_type: str = core.DEFAULT_CASE_TYPE):
        super().__init__(timeout=300)
        self.case_id = case_id
        self.reviewer_id = reviewer_id
        self.selected: list = []
        options = action_options(case_type)
        self.pick.options = options
        self.pick.max_values = len(options)

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.reviewer_id:
            await interaction.response.send_message("This menu belongs to another reviewer.", ephemeral=True)
            return False
        return True

    @discord.ui.select(placeholder="Choose one or more actions", min_values=1, max_values=4,
                       options=list(ACTION_OPTION_LIST.values()))
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
        effective = core.effective_actions(actions)
        self.reason = discord.ui.TextInput(
            label="Reason (internal, kept in the case file)",
            style=discord.TextStyle.paragraph,
            required=True,
            max_length=900,
        )
        self.add_item(self.reason)
        self.dm_text = None
        self.public_text = None
        if core.ACTION_DM in effective:
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
        effective = core.effective_actions(self.actions)
        if core.ACTION_PUBLIC in effective and not core.public_warning_allowed(case["case_type"]):
            await interaction.response.send_message(
                "❌ Public warnings are only available for scam cases.", ephemeral=True
            )
            return
        actions_io = DiscordActionIO(case["id"])
        problems = [
            p for p in (actions_io.unavailable_reason(a, case["suspect_id"]) for a in effective) if p
        ]
        if problems:
            await interaction.response.send_message(
                "❌ Can't run that yet:\n" + "\n".join(f"• {p}" for p in problems), ephemeral=True
            )
            return

        suspect_label = case["suspect_name"] or "this user"
        dm_text = (self.dm_text.value.strip() if self.dm_text else "") or core.default_dm_text(
            case["id"], case["case_type"], effective, APPEAL_TEXT
        )
        public_text = (self.public_text.value.strip() if self.public_text else "") or core.default_public_text(
            case["id"], suspect_label, case["suspect_id"]
        )
        reason = self.reason.value.strip()
        note = self.note.value.strip()

        guild = actions_io.guild()
        plan = []
        for action in core.ACTION_ORDER:
            if action in effective:
                label = core.ACTION_LABELS[action]
                if action == core.ACTION_BAN and guild is not None:
                    label += f" from {guild.name}"
                if action == core.ACTION_DM and action not in self.actions:
                    label += " (automatic with a ban or blacklist)"
                plan.append(f"• {label}")
                if action == core.ACTION_BLACKLIST and autoban_guilds():
                    plan.append(f"   ↳ pre-ban in {len(autoban_guilds())} opted-in server(s)")
        embed = discord.Embed(
            title=f"Confirm actions for case #{case['id']}",
            description=(
                f"Target: **{suspect_label}** (`{case['suspect_id']}`)\n"
                f"Type: {core.case_type_label(case['case_type'])}\n"
                "Nothing runs until you press **Confirm and run**."
            ),
            color=0xE67E22,
        )
        embed.add_field(name="Will run, in this order", value="\n".join(plan), inline=False)
        if core.ACTION_DM in effective:
            embed.add_field(name="DM text (sent with an Appeal button)", value=core.clip(dm_text, 1000), inline=False)
        if core.ACTION_PUBLIC in effective:
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
                DiscordActionIO(case["id"], will_ban=core.ACTION_BAN in self.actions),
                case, self.actions, self.reason, self.dm_text, self.public_text
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
                    decision=core.action_decision(succeeded),
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
            dm_ok = any(r.action == core.ACTION_DM and r.ok for r in results)
            failed_harsh = [
                r for r in results if r.action in (core.ACTION_BAN, core.ACTION_BLACKLIST) and not r.ok
            ]
            if dm_ok and failed_harsh:
                headline += (
                    "\n⚠️ Heads up: the DM already went out, so they were told about an action "
                    "that failed. Fix it manually."
                )
            await interaction.edit_original_response(content=f"{headline}\n{report_text}")
        finally:
            INFLIGHT.discard(self.case_id)

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.edit_message(content="Cancelled. Nothing was changed.", embed=None, view=None)


# ------------------------------------------------------------------------------
# 9b. APPEALS
# ------------------------------------------------------------------------------
APPEAL_STATUS_META = {
    core.APPEAL_OPEN: ("Pending review", 0x9B59B6),
    core.APPEAL_UPHELD: ("Rejected — decision stands", 0x95A5A6),
    core.APPEAL_OVERTURNED: ("Accepted — action lifted", 0x2ECC71),
}
APPEAL_REVIEW_BUTTONS = {
    "accept": ("Accept appeal (lift action)", discord.ButtonStyle.success, "✅"),
    "reject": ("Reject appeal", discord.ButtonStyle.secondary, "✖️"),
}
APPEAL_INFLIGHT: set = set()  # case IDs whose appeal is being filed right now


def appeal_embed(appeal, case) -> discord.Embed:
    label, color = APPEAL_STATUS_META[appeal["status"]]
    embed = discord.Embed(
        title=f"Appeal for case #{case['id']} — {label}",
        description="**Their statement (unverified):**\n" + core.code_block(appeal["reason"], 3500),
        color=color,
        timestamp=utc(appeal["created_at"]),
    )
    embed.add_field(
        name="Appellant", value=f"<@{appeal['appellant_id']}>\nID `{appeal['appellant_id']}`", inline=True
    )
    embed.add_field(
        name="Case", value=f"#{case['id']} — {core.case_type_label(case['case_type'])}", inline=True
    )
    embed.add_field(name="Original decision", value=core.decision_label(appeal["original_decision"]), inline=True)
    embed.add_field(
        name="Original reason (internal)", value=core.clip(case["decision_reason"] or "—", 1000), inline=False
    )
    link = post_url(case["thread_id"])
    if link:
        embed.add_field(name="Case file", value=f"[Open case #{case['id']}]({link})", inline=False)
    if appeal["status"] != core.APPEAL_OPEN and appeal["decided_at"]:
        embed.add_field(
            name="Ruling",
            value=core.clip(
                f"By <@{appeal['decided_by']}> on <t:{appeal['decided_at']}:f>\n{appeal['decision_reason'] or '—'}",
                1000,
            ),
            inline=False,
        )
    embed.set_footer(text="CyberBot appeal")
    return embed


async def get_thread(thread_id) -> Optional[discord.Thread]:
    if not thread_id:
        return None
    thread = bot.get_channel(thread_id)
    if thread is None:
        try:
            thread = await bot.fetch_channel(thread_id)
        except discord.HTTPException:
            return None
    return thread if isinstance(thread, discord.Thread) else None


def build_appeal_view(case_id: int) -> discord.ui.View:
    """The Appeal button that goes on the DM a punished user receives."""
    view = discord.ui.View(timeout=None)
    view.add_item(AppealButton(case_id))
    return view


def build_appeal_review_view(appeal_id: int, disabled: bool = False) -> discord.ui.View:
    view = discord.ui.View(timeout=None)
    for verdict in ("accept", "reject"):
        view.add_item(AppealReviewButton(verdict, appeal_id, disabled=disabled))
    return view


class AppealButton(
    discord.ui.DynamicItem[discord.ui.Button],
    template=r"ap:(?P<case_id>\d+)",
):
    def __init__(self, case_id: int):
        super().__init__(
            discord.ui.Button(
                label="Appeal this decision",
                style=discord.ButtonStyle.primary,
                emoji="⚖️",
                custom_id=f"ap:{case_id}",
            )
        )
        self.case_id = case_id

    @classmethod
    async def from_custom_id(cls, interaction: discord.Interaction, item: discord.ui.Button, match, /):
        return cls(int(match["case_id"]))

    async def callback(self, interaction: discord.Interaction):
        problem = core.can_appeal(core.get_case(self.case_id), interaction.user.id)
        if problem:
            await interaction.response.send_message(f"❌ {problem}", ephemeral=True)
            return
        await interaction.response.send_modal(AppealModal(self.case_id))


class AppealModal(discord.ui.Modal):
    def __init__(self, case_id: int):
        super().__init__(title=f"Appeal case #{case_id}"[:45])
        self.case_id = case_id
        self.statement = discord.ui.TextInput(
            label="Why was this a mistake?",
            style=discord.TextStyle.paragraph,
            placeholder="Explain what happened and anything the reviewer should know.",
            required=True,
            max_length=1500,
        )
        self.add_item(self.statement)

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        _ok, text = await submit_appeal(interaction.user.id, self.case_id, self.statement.value.strip())
        await interaction.followup.send(text, ephemeral=True)

    async def on_error(self, interaction: discord.Interaction, error: Exception):
        traceback.print_exception(type(error), error, error.__traceback__)
        await reply(interaction, "❌ Something went wrong while filing your appeal.")


class AppealReviewButton(
    discord.ui.DynamicItem[discord.ui.Button],
    template=r"ar:(?P<verdict>accept|reject):(?P<appeal_id>\d+)",
):
    def __init__(self, verdict: str, appeal_id: int, *, disabled: bool = False):
        label, style, emoji = APPEAL_REVIEW_BUTTONS[verdict]
        super().__init__(
            discord.ui.Button(
                label=label, style=style, emoji=emoji,
                custom_id=f"ar:{verdict}:{appeal_id}", disabled=disabled,
            )
        )
        self.verdict = verdict
        self.appeal_id = appeal_id

    @classmethod
    async def from_custom_id(cls, interaction: discord.Interaction, item: discord.ui.Button, match, /):
        return cls(match["verdict"], int(match["appeal_id"]))

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if not await user_is_reviewer(interaction.user):
            await interaction.response.send_message("❌ Only reviewers can use this panel.", ephemeral=True)
            return False
        return True

    async def callback(self, interaction: discord.Interaction):
        appeal = core.get_appeal(self.appeal_id)
        if appeal is None or appeal["status"] != core.APPEAL_OPEN:
            await interaction.response.send_message("This appeal was already decided.", ephemeral=True)
            return
        await interaction.response.send_modal(AppealDecisionModal(self.appeal_id, self.verdict == "accept"))


class AppealDecisionModal(discord.ui.Modal):
    def __init__(self, appeal_id: int, overturn: bool):
        super().__init__(title="Accept appeal" if overturn else "Reject appeal")
        self.appeal_id = appeal_id
        self.overturn = overturn
        self.note = discord.ui.TextInput(
            label="Note to the appellant (optional)",
            style=discord.TextStyle.paragraph,
            required=False,
            max_length=500,
        )
        self.add_item(self.note)

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        key = f"appeal:{self.appeal_id}"
        if key in INFLIGHT:
            await interaction.followup.send("Someone is already deciding this appeal.", ephemeral=True)
            return
        INFLIGHT.add(key)
        try:
            appeal = core.get_appeal(self.appeal_id)
            if appeal is None or appeal["status"] != core.APPEAL_OPEN:
                await interaction.followup.send("This appeal was already decided.", ephemeral=True)
                return
            case = core.get_case(appeal["case_id"])
            note = self.note.value.strip()

            reversal_text, unbanned = "", False
            if self.overturn:
                results = await core.run_reversal(DiscordActionIO(case["id"]), case)
                reversal_text = core.describe_results(results)
                if any(not r.ok for r in results):
                    await interaction.followup.send(
                        "⚠️ I couldn't fully lift the action, so the appeal is still open. Fix the problem "
                        "and press Accept again (repeating is safe):\n" + reversal_text,
                        ephemeral=True,
                    )
                    return
                unbanned = any(r.action == core.ACTION_UNBAN and r.detail.startswith("Unbanned") for r in results)

            status = core.APPEAL_OVERTURNED if self.overturn else core.APPEAL_UPHELD
            core.update_appeal(
                appeal["id"], status=status, decision_reason=note,
                decided_by=interaction.user.id, decided_at=int(time.time()),
            )
            if self.overturn:
                core.update_case(case["id"], status=core.STATUS_CLOSED, decision=core.DECISION_OVERTURNED)
            core.add_event(
                case["id"], interaction.user.id,
                "appeal_overturned" if self.overturn else "appeal_upheld", note,
            )

            dm_embed = discord.Embed(
                title=f"Appeal for case #{case['id']}",
                description=core.appeal_outcome_text(case["id"], self.overturn, note, unbanned),
                color=0x2ECC71 if self.overturn else 0x95A5A6,
            )
            dm_error = await dm_user(appeal["appellant_id"], embed=dm_embed)

            log = discord.Embed(
                title="⚖️ Appeal accepted" if self.overturn else "⚖️ Appeal rejected",
                description=f"By {interaction.user.mention}\n{core.clip(note, 1500) or '—'}",
                color=0x2ECC71 if self.overturn else 0x95A5A6,
            )
            log.add_field(
                name="Appellant DM", value="✅ Delivered" if dm_error is None else f"❌ {dm_error}", inline=True
            )
            if reversal_text:
                log.add_field(name="Reversal", value=core.clip(reversal_text, 1000), inline=False)
            for thread in (await get_thread(appeal["thread_id"]), await get_case_thread(case)):
                if thread is not None:
                    try:
                        await thread.send(embed=log, allowed_mentions=NO_MENTIONS)
                    except discord.HTTPException as exc:
                        print(f"⚠️ Could not log appeal ruling for case #{case['id']}: {exc}")
            await refresh_appeal_ui(appeal["id"])
            await refresh_case_ui(case["id"])

            text = "✅ Appeal accepted and the action lifted." if self.overturn else "✅ Appeal rejected."
            if reversal_text:
                text += "\n" + reversal_text
            if dm_error:
                text += f"\n⚠️ I couldn't DM them the result ({dm_error})."
            await interaction.followup.send(text, ephemeral=True)
        finally:
            INFLIGHT.discard(key)

    async def on_error(self, interaction: discord.Interaction, error: Exception):
        INFLIGHT.discard(f"appeal:{self.appeal_id}")
        traceback.print_exception(type(error), error, error.__traceback__)
        await reply(interaction, "❌ Something went wrong.")


async def refresh_appeal_ui(appeal_id: int) -> None:
    appeal = core.get_appeal(appeal_id)
    if appeal is None:
        return
    case = core.get_case(appeal["case_id"])
    thread = await get_thread(appeal["thread_id"])
    if thread is None or case is None:
        return
    try:
        await thread.get_partial_message(appeal["starter_message_id"]).edit(
            embed=appeal_embed(appeal, case),
            view=build_appeal_review_view(appeal_id, disabled=appeal["status"] != core.APPEAL_OPEN),
        )
    except discord.HTTPException as exc:
        print(f"⚠️ Could not refresh appeal #{appeal_id}: {exc}")


async def submit_appeal(user_id: int, case_id: int, statement: str) -> tuple:
    """Files an appeal as a new forum post. Returns (ok, message for the person)."""
    if case_id in APPEAL_INFLIGHT:
        return False, "Your appeal is already being filed."
    APPEAL_INFLIGHT.add(case_id)
    try:
        case = core.get_case(case_id)
        problem = core.can_appeal(case, user_id)
        if problem:
            return False, f"❌ {problem}"
        forum = await get_review_forum()
        if forum is None:
            return False, "❌ I can't reach the review team right now. Please try again a bit later."

        appeal_id = core.create_appeal(
            case_id=case_id, appellant_id=user_id, reason=statement, original_decision=case["decision"]
        )
        appeal = core.get_appeal(appeal_id)
        kwargs = dict(
            name=f"Appeal – Case #{case_id}"[:100],
            auto_archive_duration=core.THREAD_ARCHIVE_MINUTES,
            embed=appeal_embed(appeal, case),
            view=build_appeal_review_view(appeal_id),
            allowed_mentions=NO_MENTIONS,
        )
        tags = _tags_named(forum, ["appeal"])
        if not tags and forum.flags.require_tag and forum.available_tags:
            tags = [forum.available_tags[0]]
        try:
            try:
                created = await forum.create_thread(applied_tags=tags, **kwargs) if tags else await forum.create_thread(**kwargs)
            except discord.HTTPException:
                if not tags:
                    raise
                kwargs["view"] = build_appeal_review_view(appeal_id)
                created = await forum.create_thread(**kwargs)  # e.g. the tag is moderator-only
        except discord.HTTPException as exc:
            print(f"❌ Could not create the appeal post for case #{case_id}: {exc}")
            core.delete_appeal(appeal_id)  # nothing was filed, so they may try again
            return False, "❌ I couldn't file your appeal right now. Please try again a bit later."

        core.update_appeal(appeal_id, thread_id=created.thread.id, starter_message_id=created.message.id)
        core.add_event(case_id, user_id, "appeal_filed", core.clip(statement, 500))

        case_thread = await get_case_thread(case)
        if case_thread is not None:
            link = post_url(created.thread.id)
            note = discord.Embed(
                title="⚖️ Appeal filed",
                description=f"[Open the appeal post]({link})" if link else "See the appeal post.",
                color=0x9B59B6,
            )
            try:
                await case_thread.send(embed=note, allowed_mentions=NO_MENTIONS)
            except discord.HTTPException as exc:
                print(f"⚠️ Could not log the appeal on case #{case_id}: {exc}")
        await refresh_case_ui(case_id)
        return True, (
            f"✅ Your appeal for case #{case_id} has been filed. A reviewer will look at it "
            "and I'll message you with the result."
        )
    finally:
        APPEAL_INFLIGHT.discard(case_id)


@bot.tree.command(name="appeal", description="Appeal a CyberBot decision made against your account (once per case).")
@app_commands.allowed_installs(guilds=True, users=True)
@app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
@app_commands.describe(case_id="The case number from the notice I sent you", reason="Why you think it was a mistake")
async def appeal_cmd(
    interaction: discord.Interaction,
    case_id: int,
    reason: app_commands.Range[str, 1, 1500],
):
    await interaction.response.defer(ephemeral=True, thinking=True)
    _ok, text = await submit_appeal(interaction.user.id, case_id, reason.strip())
    await interaction.followup.send(text, ephemeral=True)


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
        detail = (
            f" ({core.decision_label(row['decision'])})"
            if row["status"] == core.STATUS_CLOSED and row["decision"] else ""
        )
        kind = core.case_type_label(row["case_type"])
        lines.append(f"**#{row['id']}** — {kind} — {label}{detail}{link}")
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


def case_export_text(case) -> str:
    def stamp(ts) -> str:
        return utc(ts).strftime("%Y-%m-%d %H:%M:%S UTC") if ts else "—"

    lines = [f"CyberBot case #{case['id']}", "=" * 40]
    lines += [
        f"Type: {core.case_type_label(case['case_type'])}",
        f"Status: {STATUS_META[status_key(case)][0]}",
        f"Filed: {stamp(case['created_at'])}",
        f"Reporter: {case['reporter_id']}",
        f"Suspect: {case['suspect_name'] or '?'} ({case['suspect_id']})",
        "Evidence: " + ("message verified by Discord" if case["verified"] else "unverified (reporter's word only)"),
        f"Source server / channel: {case['source_guild_id'] or 'DM'} / {case['source_channel_id'] or '—'}",
        f"Decision: {core.decision_label(case['decision'])}",
        f"Decision reason (internal): {case['decision_reason'] or '—'}",
        f"Decided by / at: {case['decided_by'] or '—'} / {stamp(case['decided_at'])}",
        "",
        "REPORTER'S ACCOUNT (unverified)",
        case["details"] or "(none)",
    ]
    if case["anchor_message_id"]:
        lines += [
            "",
            f"REPORTED MESSAGE {case['anchor_message_id']} sent {stamp(case['anchor_sent_at'])} "
            + ("(verified by Discord)" if case["verified"] else ""),
            case["anchor_content"] or "(no text)",
        ]
    if (case["pasted_context"] or "").strip():
        lines += ["", "PASTED CONVERSATION (unverified)", case["pasted_context"]]
    events = core.list_events(case["id"])
    if events:
        lines += ["", "TIMELINE"]
        lines += [f"{stamp(e['ts'])}  {e['kind']}  actor={e['actor_id'] or '—'}  {e['text'] or ''}" for e in events]
    appeal = core.appeal_for_case(case["id"])
    if appeal is not None:
        lines += [
            "", f"APPEAL #{appeal['id']} filed {stamp(appeal['created_at'])} by {appeal['appellant_id']}",
            f"Status: {appeal['status']}", "Statement:", appeal["reason"],
            f"Ruling: {appeal['decision_reason'] or '—'}",
        ]
    lines += ["", "Screenshots and re-hosted images live in the case's forum post."]
    return "\n".join(lines)


@bot.tree.command(name="case", description="[Reviewer] Pull up the full file for one case.")
@app_commands.describe(case_id="Case number")
@app_commands.allowed_installs(guilds=True, users=False)
@app_commands.guild_only()
@reviewer_only()
async def case_cmd(interaction: discord.Interaction, case_id: int):
    case = core.get_case(case_id)
    if case is None:
        await interaction.response.send_message(f"❌ There's no case #{case_id}.", ephemeral=True)
        return
    await interaction.response.defer(ephemeral=True)
    link = post_url(case["thread_id"])
    data = case_export_text(case).encode("utf-8")
    await interaction.followup.send(
        content=f"[Open the forum post]({link})" if link else None,
        embed=starter_embed(case),
        file=discord.File(io.BytesIO(data), filename=f"case-{case_id}.txt"),
        ephemeral=True,
    )


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
    print(f"🛡️ Pre-ban is on in {len(autoban_guilds())} server(s).")


@bot.event
async def on_ready():
    global _startup_checked
    print(f"✅ Logged in as: {bot.user.name} (ID: {bot.user.id}) — CyberBot {BOT_VERSION}")
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
_honeypot_cfg: dict = {}  # guild id -> (channel id or None, punishment). No entry = never configured.
HONEYPOT_PERMISSION = {
    core.HONEYPOT_KICK: ("kick_members", "Kick Members"),
    core.HONEYPOT_BAN: ("ban_members", "Ban Members"),
    core.HONEYPOT_TIMEOUT: ("moderate_members", "Moderate Members"),
    core.HONEYPOT_DELETE: ("manage_messages", "Manage Messages"),
}
HONEYPOT_CHOICES = [
    app_commands.Choice(name=label, value=key) for key, label in core.HONEYPOT_ACTIONS.items()
]


def load_honeypot_cache() -> None:
    _honeypot_cfg.clear()
    for row in core.all_guild_settings():
        _honeypot_cfg[row["guild_id"]] = (row["honeypot_channel_id"], row["honeypot_action"])


def save_honeypot(guild_id: int, channel_id: int, action: str, notice_message_id: Optional[int] = None) -> None:
    core.set_honeypot(guild_id, channel_id, action, notice_message_id)
    _honeypot_cfg[guild_id] = (channel_id, action)


def drop_honeypot(guild_id: int) -> None:
    core.clear_honeypot(guild_id)
    _honeypot_cfg[guild_id] = (None, core.DEFAULT_HONEYPOT_ACTION)


def honeypot_config(guild: discord.Guild) -> tuple:
    """Returns (channel or None, punishment, legacy).

    legacy is True for the old name-based trap of servers that never saved settings.
    """
    if guild.id in _honeypot_cfg:
        channel_id, action = _honeypot_cfg[guild.id]
        channel = guild.get_channel(channel_id) if channel_id else None
        return channel, (action if action in core.HONEYPOT_ACTIONS else core.DEFAULT_HONEYPOT_ACTION), False
    channel = discord.utils.get(guild.text_channels, name=core.DEFAULT_HONEYPOT_NAME)
    return channel, core.DEFAULT_HONEYPOT_ACTION, True


def honeypot_action_for(channel) -> Optional[str]:
    """The punishment if this channel is a honeypot, otherwise None. Cheap: no database access."""
    cfg = _honeypot_cfg.get(channel.guild.id)
    if cfg is None:
        return core.DEFAULT_HONEYPOT_ACTION if channel.name == core.DEFAULT_HONEYPOT_NAME else None
    channel_id, action = cfg
    if channel_id is not None and channel.id == channel_id:
        return action if action in core.HONEYPOT_ACTIONS else core.DEFAULT_HONEYPOT_ACTION
    return None


def honeypot_permission_warning(guild: discord.Guild, action: str) -> str:
    attr, label = HONEYPOT_PERMISSION[action]
    if getattr(guild.me.guild_permissions, attr):
        return ""
    return f"\n⚠️ I don't have **{label}** in this server yet, so the punishment won't work until you give it to me."


def honeypot_notice_embed(action: str) -> discord.Embed:
    embed = discord.Embed(
        title="⚠️ Active Security Honeypot",
        description=core.honeypot_notice(action),
        color=0xFF0033,
        timestamp=now(),
    )
    embed.set_footer(text="CyberBot Automated Proactive Defense")
    return embed


async def deploy_honeypot(guild: discord.Guild, raw_name: Optional[str], action: str) -> discord.TextChannel:
    overwrites = {
        guild.default_role: discord.PermissionOverwrite(read_messages=True, send_messages=True),
        guild.me: discord.PermissionOverwrite(
            read_messages=True, send_messages=True, manage_messages=True, embed_links=True),
    }
    channel = await guild.create_text_channel(
        name=core.clean_channel_name(raw_name),
        overwrites=overwrites,
        topic=core.honeypot_topic(action),
        reason="CyberBot honeypot",
    )
    save_honeypot(guild.id, channel.id, action)  # saved first, so the trap works even if the notice fails
    notice = await channel.send(embed=honeypot_notice_embed(action))
    save_honeypot(guild.id, channel.id, action, notice.id)
    return channel


async def refresh_honeypot_texts(channel: discord.TextChannel, action: str, notice_id: Optional[int]) -> Optional[int]:
    """Updates the channel topic and the notice to match the punishment. Returns the notice's message id."""
    try:
        await channel.edit(topic=core.honeypot_topic(action), reason="CyberBot honeypot punishment changed")
    except discord.HTTPException as exc:
        print(f"⚠️ Could not update the honeypot topic: {exc}")
    if notice_id:
        try:
            message = await channel.fetch_message(notice_id)
            if bot.user is not None and message.author.id == bot.user.id:
                await message.edit(embed=honeypot_notice_embed(action))
                return notice_id
        except discord.HTTPException:
            pass
    try:
        return (await channel.send(embed=honeypot_notice_embed(action))).id
    except discord.HTTPException as exc:
        print(f"⚠️ Could not post the honeypot notice: {exc}")
        return notice_id


async def trigger_honeypot(message: discord.Message, action: str) -> None:
    guild, author, channel = message.guild, message.author, message.channel
    try:
        await message.delete()
    except discord.HTTPException:
        pass
    if action == core.HONEYPOT_DELETE:
        return

    me = guild.me
    top = getattr(author, "top_role", None)
    protected = guild.owner_id == author.id or (top is not None and me is not None and top >= me.top_role)
    if protected:
        await channel.send(
            embed=discord.Embed(
                title="⚠️ Honeypot Triggered — Action Restricted",
                description=(
                    f"User: {author.mention} ({author.id})\n"
                    "❌ I can't punish them: their role is higher than or equal to mine, or they own the server."
                ),
                color=0xF1C40F,
                timestamp=now(),
            ),
            allowed_mentions=NO_MENTIONS,
            delete_after=12,
        )
        return

    reason = "[CyberBot Honeypot] Triggered security trap channel."
    try:
        if action == core.HONEYPOT_KICK:
            await guild.kick(author, reason=reason)
        elif action == core.HONEYPOT_BAN:
            # also sweeps up what a spam bot posted in the last hour
            await guild.ban(author, reason=reason, delete_message_seconds=3600)
        elif action == core.HONEYPOT_TIMEOUT:
            await author.timeout(datetime.timedelta(hours=core.HONEYPOT_TIMEOUT_HOURS), reason=reason)
    except discord.Forbidden:
        needed = HONEYPOT_PERMISSION[action][1]
        await channel.send(
            embed=discord.Embed(
                title="⚠️ Honeypot Error",
                description=f"❌ Permission Error: I lack the **{needed}** permission.",
                color=0xFF0033,
            ),
            delete_after=10,
        )
    except Exception as exc:
        print(f"❌ Error handling honeypot execution: {exc}")
    else:
        await channel.send(
            embed=discord.Embed(
                title="🚨 Honeypot Trap Triggered",
                description=(
                    f"User: {author} ({author.id})\n"
                    f"🛡️ They triggered the automated trap and have been {core.HONEYPOT_PHRASES[action]}."
                ),
                color=0xFF0033,
                timestamp=now(),
            ),
            allowed_mentions=NO_MENTIONS,
            delete_after=8,
        )


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
        existing, action, _legacy = honeypot_config(guild)
        if existing:
            await interaction.response.send_message(
                f"⚠️ The honeypot trap channel is already active in {existing.mention} "
                f"({core.HONEYPOT_ACTIONS[action]}).", ephemeral=True)
            return
        try:
            channel = await deploy_honeypot(guild, None, core.DEFAULT_HONEYPOT_ACTION)
            await interaction.response.send_message(
                f"✅ Successfully deployed the security honeypot trap in {channel.mention} "
                f"(punishment: {core.HONEYPOT_ACTIONS[core.DEFAULT_HONEYPOT_ACTION]}). "
                "Want another name or punishment? Use `/honeypot-create` or `/honeypot-punishment`."
                + honeypot_permission_warning(guild, core.DEFAULT_HONEYPOT_ACTION),
                ephemeral=True)
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
            "• 🪤 **Honeypot Trap:** Deploys a trap channel that punishes spambots (kick by default). "
            "Customize it with `/honeypot-create` and `/honeypot-punishment`."
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
    report_type="Kind of case (default: scam)",
)
@app_commands.choices(report_type=TYPE_CHOICES)
@app_commands.allowed_installs(guilds=True, users=False)
@is_bot_owner()
async def add_scammer(interaction: discord.Interaction, user_id: str, reason: str, report_type: str = core.CASE_SCAM):
    uid = core.extract_user_id(user_id)
    if uid is None:
        await interaction.response.send_message("❌ User ID must be numeric.", ephemeral=True)
        return
    await interaction.response.defer(ephemeral=True, thinking=True)
    if not core.blacklist_add(uid, reason, None, report_type):
        await interaction.followup.send(f"❌ User ID {uid} is already logged in the database.", ephemeral=True)
        return
    done, failed = await preban_everywhere(uid, None)
    text = f"✅ Added threat actor: User ID {uid} — Reason: {reason}"
    if done or failed:
        text += f"\nPre-banned in {done} opted-in server(s)" + (f" ({failed} failed)." if failed else ".")
    await interaction.followup.send(text, ephemeral=True)


@bot.tree.command(
    name="remove-scammer",
    description="[Owner Only] Remove a user from the threat database (and lift CyberBot's pre-bans).",
)
@app_commands.describe(user_id="The Discord User ID", lift_prebans="Also unban them in opted-in servers (default: yes)")
@app_commands.allowed_installs(guilds=True, users=False)
@is_bot_owner()
async def remove_scammer(interaction: discord.Interaction, user_id: str, lift_prebans: bool = True):
    uid = core.extract_user_id(user_id)
    if uid is None:
        await interaction.response.send_message("❌ User ID must be numeric.", ephemeral=True)
        return
    await interaction.response.defer(ephemeral=True, thinking=True)
    case_id = blacklist_case_id(uid)
    if not core.blacklist_remove(uid):
        await interaction.followup.send(f"❌ User ID {uid} isn't in the database.", ephemeral=True)
        return
    text = f"✅ Removed {uid} from the database."
    if lift_prebans:
        lifted, problems = await lift_cyberbot_bans(
            autoban_guilds(), uid, case_id, "[CyberBot] Removed from the blacklist"
        )
        text += f"\nUnbanned in {len(lifted)} opted-in server(s)."
        if problems:
            text += "\n⚠️ " + "; ".join(problems)
    text += "\nA ban in the main server is separate: unban there by hand if needed."
    await interaction.followup.send(text, ephemeral=True)


@bot.tree.command(
    name="autoban",
    description="[Admin] Pre-ban everyone on the CyberBot blacklist, now and whenever it grows.",
)
@app_commands.describe(
    enabled="Turn pre-banning on or off for this server",
    sync_now="When turning it on: also ban everyone already on the blacklist right now",
)
@app_commands.allowed_installs(guilds=True, users=False)
@app_commands.guild_only()
@app_commands.checks.has_permissions(ban_members=True)
async def autoban(interaction: discord.Interaction, enabled: bool, sync_now: bool = False):
    guild = interaction.guild
    if not enabled:
        core.set_autoban(guild.id, False)
        await interaction.response.send_message(
            "✅ Pre-ban is **off**. Bans CyberBot already placed here stay until you lift them.", ephemeral=True)
        return
    if not guild.me.guild_permissions.ban_members:
        await interaction.response.send_message(
            "❌ I need the **Ban Members** permission here first.", ephemeral=True)
        return
    await interaction.response.defer(ephemeral=True, thinking=True)
    core.set_autoban(guild.id, True, interaction.user.id)
    text = (
        "✅ Pre-ban is **on**. Anyone on the CyberBot blacklist is banned here by ID, including before "
        "they join, with a generic reason. If an appeal is accepted, I lift the ban again."
    )
    if sync_now:
        entries = core.blacklist_entries()
        done = failed = 0
        for entry in entries:
            problem = await preban_user(guild, entry["user_id"], entry["case_id"])
            if problem:
                failed += 1
            else:
                done += 1
            await asyncio.sleep(0.4)
        text += f"\nSynced the blacklist: {done} banned, {failed} could not be banned (of {len(entries)})."
    await interaction.followup.send(text, ephemeral=True)


@bot.tree.command(
    name="honeypot-create",
    description="[Admin] Create a honeypot channel with your own name and punishment.",
)
@app_commands.describe(
    name="Channel name (default: security-honeypot)",
    punishment="What happens to whoever posts there (default: kick)",
)
@app_commands.choices(punishment=HONEYPOT_CHOICES)
@app_commands.allowed_installs(guilds=True, users=False)
@app_commands.guild_only()
@app_commands.checks.has_permissions(manage_channels=True)
async def honeypot_create(
    interaction: discord.Interaction,
    name: Optional[app_commands.Range[str, 1, 100]] = None,
    punishment: str = core.DEFAULT_HONEYPOT_ACTION,
):
    guild = interaction.guild
    existing, action, _legacy = honeypot_config(guild)
    if existing:
        await interaction.response.send_message(
            f"⚠️ A honeypot is already active in {existing.mention} ({core.HONEYPOT_ACTIONS[action]}). "
            "Use `/honeypot-punishment` to change what it does, or `/honeypot-remove` first.",
            ephemeral=True)
        return
    await interaction.response.defer(ephemeral=True, thinking=True)
    try:
        channel = await deploy_honeypot(guild, name, punishment)
    except discord.Forbidden:
        await interaction.followup.send("❌ **Permission Error:** I lack the `Manage Channels` permission.", ephemeral=True)
        return
    except discord.HTTPException as exc:
        await interaction.followup.send(f"❌ Discord refused to create the channel ({exc.status}).", ephemeral=True)
        return
    await interaction.followup.send(
        f"✅ Honeypot created in {channel.mention}. Punishment: **{core.HONEYPOT_ACTIONS[punishment]}**."
        + honeypot_permission_warning(guild, punishment),
        ephemeral=True)


@bot.tree.command(
    name="honeypot-punishment",
    description="[Admin] Change what happens to whoever posts in the honeypot.",
)
@app_commands.describe(punishment="The new punishment")
@app_commands.choices(punishment=HONEYPOT_CHOICES)
@app_commands.allowed_installs(guilds=True, users=False)
@app_commands.guild_only()
@app_commands.checks.has_permissions(manage_channels=True)
async def honeypot_punishment(interaction: discord.Interaction, punishment: str):
    guild = interaction.guild
    channel, _old, _legacy = honeypot_config(guild)
    if channel is None:
        await interaction.response.send_message(
            "⚠️ There's no honeypot here yet. Create one with `/honeypot-create`.", ephemeral=True)
        return
    await interaction.response.defer(ephemeral=True, thinking=True)
    row = core.get_guild_settings(guild.id)
    notice_id = row["honeypot_notice_message_id"] if row is not None else None
    notice_id = await refresh_honeypot_texts(channel, punishment, notice_id)
    save_honeypot(guild.id, channel.id, punishment, notice_id)
    await interaction.followup.send(
        f"✅ {channel.mention} now punishes with: **{core.HONEYPOT_ACTIONS[punishment]}**."
        + honeypot_permission_warning(guild, punishment),
        ephemeral=True)


@bot.tree.command(
    name="honeypot-remove",
    description="[Admin] Turn the honeypot off.",
)
@app_commands.describe(delete_channel="Also delete the honeypot channel (default: no)")
@app_commands.allowed_installs(guilds=True, users=False)
@app_commands.guild_only()
@app_commands.checks.has_permissions(manage_channels=True)
async def honeypot_remove(interaction: discord.Interaction, delete_channel: bool = False):
    guild = interaction.guild
    channel, _action, legacy = honeypot_config(guild)
    if channel is None:
        await interaction.response.send_message("⚠️ There's no honeypot configured here.", ephemeral=True)
        return
    drop_honeypot(guild.id)
    text = "✅ The honeypot is **off**. Messages in that channel are no longer punished."
    if delete_channel:
        try:
            await channel.delete(reason="CyberBot honeypot removed")
            text += " The channel was deleted."
        except discord.HTTPException:
            text += f" I couldn't delete {channel.mention}; you can delete it yourself."
    else:
        text += f" {channel.mention} is still there; delete it if you don't need it."
    await interaction.response.send_message(text, ephemeral=True)


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
    honeypot_channel, honeypot_action, _legacy = honeypot_config(guild)
    forum = await get_review_forum()

    alerts_status = f"🟢 Active ({alerts_channel.mention})" if alerts_channel else "🔴 Not Configured"
    if honeypot_channel:
        honeypot_status = f"🟢 Active ({honeypot_channel.mention})\nPunishment: {core.HONEYPOT_ACTIONS[honeypot_action]}"
    elif _honeypot_cfg.get(guild.id, (None,))[0]:
        honeypot_status = "🟠 The honeypot channel is missing. Run `/honeypot-create`."
    else:
        honeypot_status = "🔴 Not Configured"
    if forum is None:
        intake_status = "🔴 Review forum unreachable"
    elif forum.guild.id == guild.id:
        intake_status = f"🟢 Active ({forum.mention})"
    else:
        intake_status = "🟢 Active (review forum is in another server)"
    autoban_status = "🟢 On" if core.autoban_enabled(guild.id) else "⚪ Off (turn on with `/autoban`)"

    embed = discord.Embed(
        title=f"🛡️ CyberBot Security Dashboard — {guild.name}",
        description="Real-time operational status of CyberBot security modules on this server.",
        color=0x2ECC71,
        timestamp=now(),
    )
    embed.add_field(name="📢 Threat Alerts Feed", value=alerts_status, inline=True)
    embed.add_field(name="🪤 Honeypot Trap", value=honeypot_status, inline=True)
    embed.add_field(name="📥 Report Intake", value=intake_status, inline=True)
    embed.add_field(name="🔨 Pre-ban", value=autoban_status, inline=True)
    embed.add_field(
        name="⚡ Core Specs",
        value=f"• CyberBot {BOT_VERSION}\n• Engine: discord.py {discord.__version__}",
        inline=False,
    )

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

    if isinstance(message.channel, discord.TextChannel):
        action = honeypot_action_for(message.channel)
        if action is not None:
            await trigger_honeypot(message, action)
            return

    await bot.process_commands(message)


@bot.event
async def on_member_join(member: discord.Member):
    """Pre-ban: block blacklisted IDs the moment they join an opted-in server."""
    if not core.autoban_enabled(member.guild.id) or not core.is_blacklisted(member.id):
        return
    problem = await preban_user(member.guild, member.id, blacklist_case_id(member.id))
    channel = discord.utils.get(member.guild.text_channels, name=ALERT_CHANNEL_NAME)
    if channel is None:
        if problem:
            print(f"⚠️ Could not pre-ban {member.id} in {member.guild.name}: {problem}")
        return
    embed = discord.Embed(
        title="🛡️ Blacklisted user blocked" if not problem else "⚠️ Blacklisted user joined",
        description=(
            f"{member} (`{member.id}`) is on the CyberBot blacklist and was banned automatically."
            if not problem else
            f"{member} (`{member.id}`) is on the CyberBot blacklist but I couldn't ban them: {problem}."
        ),
        color=0xFF0033 if not problem else 0xF1C40F,
        timestamp=now(),
    )
    try:
        await channel.send(embed=embed, allowed_mentions=NO_MENTIONS)
    except discord.HTTPException:
        pass


@bot.event
async def on_guild_channel_delete(channel):
    cfg = _honeypot_cfg.get(channel.guild.id)
    if cfg is not None and cfg[0] == channel.id:
        drop_honeypot(channel.guild.id)  # the honeypot channel was deleted by hand


# ------------------------------------------------------------------------------
# 14. BOT EXECUTION
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    if not TOKEN:
        print("❌ ERROR: DISCORD_TOKEN is missing!")
    else:
        bot.run(TOKEN)
