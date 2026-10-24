CyberBot Privacy Notice
Version 1.1.0 · Last updated 23 October 2026
CyberBot is a Discord bot run by CyberByte. It exists to help communities deal with scams and cyberbullying. This page says what it stores, why, who can see it, and how long it is kept.
> **Early access notice:** CyberBot is in early access. **All data described below is currently kept and cannot yet be deleted on request.** There is no delete or purge feature, and we are not able to process deletion requests at this time. Please read the "Retention" section before you use the bot.
Who is responsible
CyberByte (the bot's owner and sole reviewer) decides what is stored and why. Contact: bruno09213 on discord.
What CyberBot stores
When someone files a report
The reporter's Discord user ID.
The reported user's Discord user ID and username at the time of the report.
The type of report (scam, cyberbullying or other).
If a message was reported: its text, its ID, when it was sent, and the server and channel it came from (or that it came from a DM).
What the reporter wrote, any conversation they pasted, and anything they add later (text and screenshots).
Screenshots and image attachments. Only images are copied, and they are copied into a private review forum, not into the bot's database. Other file types are not copied.
Whether the message was verified by Discord or only supplied by the reporter.
When a case is reviewed
The decision (dismissed, or which actions were taken), the reviewer's internal reason, who decided and when.
A timeline of events on the case (for example "more info requested", "actions run", "appeal filed").
Whether the bot could DM the reporter.
When someone appeals
The appellant's user ID, their statement, the original decision, and the reviewer's ruling and note.
The blacklist
If someone is blacklisted: their user ID, the reason given, the case number and the case type.
Server settings
For servers that use the honeypot: the honeypot channel ID, its punishment and the notice message ID.
For servers that turn on pre-ban: the server ID, who turned it on and when.
What CyberBot does not store
It does not keep a log of ordinary messages. Messages in a server are only checked to see whether they were posted in a honeypot channel. A honeypot message is deleted and its content is not saved.
It does not store IP addresses, emails, payment details or anything outside Discord.
Direct messages to the bot are only used to add proof to your report or to file an appeal. They are not otherwise kept as a chat log. What you send for those purposes is stored as described above.
Why we use it
To review reports and keep a record of how each case was decided.
To act on confirmed cases: DM warnings, public scam warnings, bans, and the blacklist.
To let people appeal, and to undo actions when an appeal is accepted.
To protect other communities that choose to use the blacklist, the honeypot or pre-ban.
We do not sell data, show ads or use the data for anything else.
Who can see it
The reviewer(s): the bot owner and anyone given the reviewer role can see full case files, including the reporter's identity, evidence, and internal reasons.
The reported user: they are never told who reported them. If action is taken, they get a DM with the case number, the kind of report and how to appeal. The DM does not include the reporter, the evidence or the internal reason.
The reporter: they are told when their report has been reviewed, plus an optional note from the reviewer. They are not told what action was taken.
Other servers using CyberBot: servers that run `/scan-members` can see the user ID and the reason text of blacklisted users who are in their server. Servers that turn on pre-ban only apply the ban, with a generic reason that does not include internal notes or the reporter. Reviewers write blacklist reasons knowing admins of other servers may read them.
Audit logs: a ban in the CyberByte server is recorded in that server's audit log with the case number and the reviewer's reason.
Public warnings: for confirmed scam cases only, a warning naming the user and their ID may be posted in the warnings channel. Harassment cases are never announced publicly.
Discord: the bot runs on Discord, which handles its own data under Discord's own terms and privacy policy.
Where it is kept
Case data is in a database file on the machine that hosts the bot, and the blacklist is a JSON file next to it. 
Evidence images and case posts are in a private Discord forum that only reviewers can access.
Access to the host and to the forum is limited to the bot's owner and reviewers.
Retention (early access)
Everything is kept indefinitely. Cases, evidence, decisions, appeals and the blacklist are retained so that a case can be pulled back up later, for example if someone appeals, reoffends or a decision is questioned.
Deletion on request is not available yet. This applies to reporters, reported users and appellants alike.
An accepted appeal does not erase the case. It lifts the ban and removes the user from the blacklist and the case is marked as overturned, but the case file stays on record.
Dismissed reports are also kept.
When the early-access period ends we plan to add retention limits and a way to request deletion or a copy of your data. This notice will be updated before that happens.
If you do not want your information stored under these terms, please do not file a report, and think carefully before pasting private conversations into one.
Your choices today
Reporting is optional and you can decide how much to include.
Appeals: if action was taken against you, you can appeal once per case (the Appeal button, `/appeal`, or a DM saying `appeal #N` and your explanation).
Adding proof: reporters can add more proof to their own open reports.
Server admins can turn the honeypot, pre-ban and alerts on or off in their own servers.
Questions or concerns: contact us using the details above. We can answer questions and review appeals, but we cannot delete data yet.
Children
Discord requires users to be at least 13 (or older where local law says so). CyberBot is not designed for younger children and we do not knowingly collect data from them. Reports about harassment may include minors as reporters or reported users. Such reports are handled like any other.
Changes to this notice
We will update this page when the bot's data practices change and change the date at the top. Significant changes, especially the end of the "cannot be deleted" period, will be announced in the CyberByte server.
