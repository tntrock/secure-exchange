# Secure Exchange: User Manual

[繁體中文](user-manual.md)

This manual explains how to send and receive files with the Secure Exchange system. For installation, configuration and maintenance, see the [Administrator Manual](admin-manual.en.md).

## Contents

- [Which kind of user are you?](#which-kind-of-user-are-you)
- **Part 1: Staff**
  - [1. Signing in and two-factor authentication](#1-signing-in-and-two-factor-authentication)
  - [2. My files](#2-my-files)
  - [3. Creating a share](#3-creating-a-share)
  - [4. Managing shares](#4-managing-shares)
  - [5. Upload requests: collecting files from outsiders](#5-upload-requests-collecting-files-from-outsiders)
  - [6. Vendor accounts](#6-vendor-accounts)
- **Part 2: External users**
  - [7. Receiving shared files (one-time share recipients)](#7-receiving-shared-files-one-time-share-recipients)
  - [8. Uploading files for an upload request](#8-uploading-files-for-an-upload-request)
  - [9. Using a vendor account](#9-using-a-vendor-account)
- [10. FAQ](#10-faq)

## Which kind of user are you?

| Role | How you get in | Read |
|---|---|---|
| **Staff** (including administrators) | An account issued by your company; sign in with email and password | Part 1 |
| **One-time share recipient** | You received a share invitation email; open the link and verify with an emailed code | Section 7 |
| **Uploader** | You received an email asking you to upload files; verify with an emailed code | Section 8 |
| **Vendor** | An outside person you work with long-term, with their own account (password plus two-factor authentication) | Section 9 |

You can switch between **繁體中文** and **English** at the top right of the screen.

---

# Part 1: Staff

## 1. Signing in and two-factor authentication

### Signing in

1. Open the system URL, enter your **Email** and **Password**, and click "Log in".
2. If two-factor authentication is enabled, enter the 6-digit **code** from your authenticator app and click "Verify".
3. After signing in you land on "My files". Your session lasts 12 hours by default, after which you must sign in again; if you are signed out because of a timeout, signing back in returns you to the page you were on.

> Entering a wrong password or code too many times in a row blocks you temporarily (the screen shows "Too many attempts, try again later"). Wait a minute or two and try again.
>
> After entering your password you must complete the code step within 10 minutes, otherwise you have to sign in again.

### Signing in with a domain account

If your company has enabled domain sign-in (the login page shows a "Domain account" form), enter your domain account name (for example `jsmith` or `jsmith@corp.example`) in the "Username" field of the "Domain account" form and your domain password in the "Password" field, then click "Log in". Your account is created automatically the first time you sign in.

- Domain accounts do not use this system's two-factor authentication; use your domain's multi-factor authentication as your company requires.
- If you see "The domain server is temporarily unreachable. Try again later or use a local account", try again later.
- If you see "This domain account's email is already used by another domain account. Contact an administrator", tell an administrator.
- "Invalid email or password" means you should check your domain password; the same message appears when the account is disabled in the domain.
- To make sure the account is still valid, the system checks with the domain about every 15 minutes; if the account has been disabled or the domain is temporarily unreachable, you are signed out.

### Signing in with single sign-on

If your company has enabled single sign-on (the login page shows a "Sign in with Microsoft" button, separated from the form by "or"), click the button and sign in on your company's Microsoft sign-in screen (including any multi-factor authentication your company requires). You are then returned to the system and land on "My files". Your account is created automatically the first time you sign in.

- A single sign-on account is separate from local and domain accounts: even with the same email they do not share files, so always sign in the same way.
- Single sign-on accounts do not use this system's two-factor authentication; use Microsoft's multi-factor authentication as your company requires.
- Clicking "Log out" in this system only signs you out of this system, not out of Microsoft. On a shared computer, sign out of Microsoft separately.
- The session lasts as long as a normal sign-in (12 hours by default), after which you must sign in again.
- "Sign-in was cancelled" means you clicked cancel on the Microsoft screen or were refused; click the button again if you need to.
- If you see "Single sign-on failed, please try again", go back to the login page and click the button again; if it keeps happening, tell an administrator.
- If you see "The identity provider is temporarily unreachable. Try again later or use a local account", try again later, or sign in with a local account.
- If you see "This single sign-on account's email is already used by another single sign-on account. Contact an administrator", your email is already taken by another single sign-on account in the system; tell an administrator.
- If an administrator has disabled your account, you see "Single sign-on failed, please try again" and retrying does not help; contact an administrator.

### Activating your account (first time)

After an administrator creates your account, you receive an activation invitation email.

1. Open the link in the email. It is valid for 7 days and can be used once; if an administrator invites you again, the old link stops working.
2. Set a **password** (at least 12 characters) and enter it again to confirm.
3. If the system requires two-factor authentication, the page shows a QR code; scan it with an authenticator app and enter the 6-digit code.
4. When done, you return to the login page; sign in with your email and new password.

If the page says the link is no longer valid, ask an administrator to invite you again.

### Two-factor authentication required at first login

If an administrator turns on "Require two-factor authentication for local staff and administrators" on the "Rules" page and you have not set it up yet, you go straight to the setup screen after entering your password and must finish it before you can use anything else. The steps are the same as in "Setting up two-factor authentication" below.

### Setting up two-factor authentication (strongly recommended)

1. On the "My files" page, click "Two-factor settings".
2. Click "Start setup" and scan the QR code with an authenticator app on your phone (for example Google Authenticator, Microsoft Authenticator or 1Password).
3. Enter the 6-digit code shown in the app and click "Enable".
4. From then on, every sign-in requires a code.

> If you lose your phone or change devices, ask a system administrator to reset your two-factor authentication; after the reset, sign in with your password and set it up again.

### Log out

Click "Log out" at the top of the screen. Always log out on a shared computer.

## 2. My files

"My files" lists the files you uploaded, plus files others sent to you through upload requests or as vendors.

### Uploading files

- Drag files into the "Drop files here, or click to choose" area, or click it to choose files. You can select several at once.
- While uploading you can "Pause", "Resume" or "Cancel".
- **Resumable after a disconnection**: if the network drops or you close the tab, choose the same file again and the upload continues where it stopped instead of starting over.
- Files are always stored encrypted on the server.

### Columns in the file list

| Column | Description |
|---|---|
| Name | The file name. For files others uploaded to you, the source is shown below it: "Upload request" (click to open that request) or "Vendor upload: vendor email". |
| Size, Uploaded, SHA-256 | SHA-256 is a fingerprint of the file; use it to check whether two files are identical. |
| Preview | How ready the online preview is (see the table below). |
| Scan | Only for externally uploaded files; see [Scan status](#scan-status). |

**Preview status**

| Shown | Meaning |
|---|---|
| Processing | The server is generating the preview, usually a few seconds to a few minutes. |
| Ready | Can be viewed online, and can be put in a "view-only" share. |
| Not previewable | This file type cannot be viewed online (for example archives); it can only be shared with "Allow download". |
| Too large to preview | Exceeds the preview size limit set for the system. |
| Preview failed | Conversion failed (for example the file is corrupted). |

Formats that can be previewed online: PDF, Word/Excel/PowerPoint, OpenDocument, RTF, CSV, plain text and common source code, HTML; JPEG, PNG, GIF, WebP, BMP and TIFF images; MP4, MOV, M4V, MKV, WebM and AVI video.

### Scan status

Files that outside people (uploaders, vendors) send you are scanned for viruses first:

| Badge | What you can do |
|---|---|
| Scanning | Still waiting for the scan; the file cannot be downloaded, previewed or shared yet. The page updates itself. |
| No virus found | Works like any other file. |
| Infected | A virus was detected (its name is shown). The file is quarantined and cannot be downloaded, previewed or shared; you can only delete it. You and the administrators both receive a notification email. |
| Not scanned (too large) | Over the scan size limit and released without scanning. **Be especially careful**: open it only if you trust the source. |
| Scan failed | Could not be scanned after several attempts; blocked like an infected file. |

Files you upload yourself are not scanned and show no badge.

### Downloading and deleting

- Click "Download" to get the original file. Downloading your own files adds no marks.
- Click "Delete" and confirm to delete a file. If the file is in a share, recipients can no longer see it (the share shows "(deleted)").

## 3. Creating a share

A share lets you hand files safely to people outside your company. Recipients do not need an account; they prove their identity with an emailed code. You can also share with vendors who already have an account.

### Steps

1. In "My files", tick the files to share (up to 100) and click "Create share (N selected)".
2. Fill in the dialog:

| Field | Description |
|---|---|
| Recipients | Recipients' emails, one per line or separated by commas. |
| Vendors | If there are active vendor accounts, tick them in the list, or search by name, email or organisation in "Filter vendors". Recipients and vendors together may number at most 50, and at least one is required. |
| Allow download | Ticked: recipients can download the files. Unticked: **view-only**; recipients can only watch in the browser and cannot download. |
| Watermark | When ticked, every page and video segment the recipient sees carries semi-transparent text: tracking code, time, IP and the recipient's email. If download is allowed, downloaded files are watermarked too (see the notes below). |
| Expires at | From 1 hour up to the maximum set by the administrator; the default is also set by the administrator. The link stops working automatically after that. |
| Max views (optional) | Optional. Each completed verification by a recipient counts as one view. |
| Allowed IPs/CIDRs (optional, one per line) | Optional. Access is allowed only from these network locations, for example a partner company's fixed IP. |
| Message (optional) | Optional; shown in the invitation email and on the recipient page (up to 2000 characters). |

3. Click "Create". Each email recipient receives an invitation email; vendors receive a notification email and should sign in and look under "Shared with me".

### Notices that may appear in the dialog

| Notice | Meaning and what to do |
|---|---|
| Some selected files are not ready for preview; a view-only share may be rejected | Files whose preview is not ready cannot go in a view-only share. Wait for the preview to finish, or allow download instead. |
| With the watermark on, recipients receive these Office files as watermarked PDFs: | For Word, Excel, PowerPoint and similar files with "Allow download" plus "Watermark", recipients download a watermarked PDF. If they need the editable original, turn the watermark off. |
| These files cannot be fully trace-marked, so a leaked copy can only be traced through the download log: | If these files leak, they can only be traced through the download records; nothing in the file itself shows who leaked it. |
| These files get no embedded mark; only the downloader and the file fingerprint are recorded: | For example video and archives. The system still records who downloaded which version. |
| The administrator blocks sharing these files for download with a watermark. Turn off download or the watermark, or remove them: | The administrator has set that files that cannot be marked may not be released this way. Turn off download or the watermark, or remove these files. |

### Options set by the administrator

Administrators can enforce some options for everyone. Enforced options are greyed out in the dialog and cannot be changed, and are labelled "Set by administrator":

- When the administrator forbids downloads, "Allow download" is unticked and locked, and every share is view-only; a share containing files that cannot be previewed online then cannot be created.
- When the administrator requires a watermark on everything, "Watermark" is ticked and locked.

Error messages that may appear when creating a share:

| Message | Meaning and what to do |
|---|---|
| Download is disabled by the administrator | Shares that allow download cannot be created right now; make the share view-only. |
| The administrator requires a watermark | Tick "Watermark". |
| A recipient's email domain is not allowed / A selected vendor's email domain is not allowed | The administrator restricts which email domains can be shared with; use allowed recipients instead. |
| The selected files exceed the maximum share size | The total size of the files in one share is over the administrator's limit; split them into several shares. |
| Expiry must be between 1 hour and the maximum allowed from now | The expiry is later than the maximum number of days the administrator allows. |
| Some files cannot be previewed online; allow download instead | These files cannot be previewed, and if download cannot be allowed right now they cannot be shared; contact an administrator. |

When an administrator tightens the rules (forbidding downloads, requiring watermarks, restricting email domains), **shares you already created are affected immediately**, and you receive a summary email listing the affected shares. For example, after downloads are forbidden, a share that allowed download becomes view-only. Downloading your own files is not affected.

Also, if you see "File is too large" or "Storage is full" when uploading, you have exceeded the administrator's per-file size limit or your storage quota; delete files you no longer need, or contact an administrator. The administrator may also set a retention period: files are deleted automatically once every share and upload request containing them has ended for longer than that many days. Files that were never shared are not deleted automatically.

### Download tracking

Every download by a recipient produces a tracking code (for example `SX-ABCD123456`). Depending on the file type, the system embeds the code in the file (PDF metadata, an invisible watermark in images, document properties in Office files, and so on). If a file leaks, an administrator can use "Leak tracing" to find out which recipient downloaded it, when, and from which IP.

## 4. Managing shares

Click "My shares" at the top to see all your shares, with creation time, expiry, number of files, number of recipients, views and status (Active / Expired / Revoked). Click a share to open "Share details":

- **Settings**: allow download, watermark, expiry, view limit, IP restriction. If an administrator rule has forced one of these (download ban, always watermark), the details page shows the value actually in effect and notes "Changed by an administrator rule".
- **Files**: the files in the share.
- **Recipients**: when each recipient first opened the share and last accessed it. Vendor recipients carry a "Vendor" badge.
- **Add recipients**: add email recipients or vendors to a share that has not expired; they receive their own invitation emails.
- **Revoke** (a single recipient): cancels only that recipient's access.
- **Revoke entire share**: all recipients lose access immediately, and anyone currently viewing is disconnected.
- **Activity history**: the share's access history (latest 200 entries): who opened, viewed or downloaded which file, and when.

**Notification emails**: you receive an email the first time each recipient opens a share and the first time they download each file; later repeated opens and downloads send no more email. You can turn these notifications off in "Settings"; see "Notification settings" below.

### Notification settings

Click "Settings" at the top (`/settings`). In the "Email notifications" section you choose which notification emails you receive, with three switches:

- **When a recipient opens my share for the first time**
- **When a recipient downloads my files**
- **When someone uploads to my upload request** (this also covers files vendors upload to you, including the upload alert for "Not scanned (too large)" files)

Virus alerts and scan-error emails are **always sent** and cannot be turned off. The Settings page also has a link to "Two-factor authentication".

## 5. Upload requests: collecting files from outsiders

An upload request lets people without an account send files to you, for example when you ask a customer for documents.

### Creating a request

1. Click "Upload requests" at the top.
2. Under "New request", fill in:

| Field | Description |
|---|---|
| Uploaders | Emails allowed to upload, one per line or comma-separated, up to 50. Only these people can use the link. |
| Expires on | Valid until the end of that day, at most the system's maximum share lifetime. |
| Max files, Max total size (GB) | Limits for the whole request, shared by all uploaders. |
| Allowed extensions | Optional, for example `pdf, docx`. Empty means no restriction. The upload page shows the intersection of this list and the administrator's site-wide rule; if the two have nothing in common, the upload page says no file types are accepted right now. |
| Message to uploaders (optional) | Optional; shown in the invitation email and on the upload page. |

3. Click "Create request". Each uploader receives an invitation email.

### Viewing and revoking

- "My requests" lists all requests with their status (Active / Expired / Revoked) and the number and size of files received.
- Open a request to see the **upload link** (click "Copy link" to forward it yourself), when each uploader first opened it and last accessed it, and every uploaded file with its scan status.
- "Revoke request" makes the link stop working immediately. Files already uploaded stay in your "My files".
- You receive a notification email for each file whose scan finishes. In "My files" these files show "Upload request" as their source.

## 6. Vendor accounts

Vendor accounts are for outside people you work with **often**. Unlike a one-time share, a vendor has their own account (password plus mandatory two-factor authentication), can see everything shared with them under "Shared with me", and can upload files directly to you.

### Creating a vendor account

1. Click "Vendors" at the top.
2. Under "New vendor account", fill in the email, display name, organisation (optional; you can pick an existing one) and expiry date (from tomorrow up to three years away; the default is one year from now).
3. Click "Create and invite".

Depending on system settings, the result may be:

- **Direct invitation**: the vendor receives the invitation email immediately and the status is "Invited".
- **Pending approval**: an administrator must approve before the invitation is sent, and the status is "Pending approval".
- **You do not have permission to do that**: the system is set so that only administrators can create vendors; contact an administrator.

### Vendor status

| Status | Meaning |
|---|---|
| Pending approval | Waiting for administrator approval. |
| Rejected | An administrator rejected the request. |
| Invited | The invitation has been sent; the vendor has not activated the account yet. |
| Active | The vendor has activated the account and can sign in. |
| Disabled | Disabled; cannot sign in, and any signed-in sessions end immediately. |
| Expired | Past the expiry date; cannot sign in. |

### Managing vendors

The creator and administrators can do the following to a vendor:

- **Disable / Enable**: temporarily turn the account off or back on.
- **Reinvite**: when the status is "Invited", send a fresh invitation; the old invitation link stops working at once. Use this when the vendor did not get the email or the link expired (invitations are valid for 7 days).
- **Change expiry**: lengthen or shorten the account's lifetime; this is also how you extend an account that has already expired.

"Pending approval" and "Rejected" vendors have no actions; **Enable** appears only for "Disabled" vendors. For a rejected vendor, the email can be added as a vendor again (a new request).

### Sharing with vendors and receiving vendor uploads

- Any staff member can share files with any "Active" vendor (see [Creating a share](#3-creating-a-share)).
- Vendors can upload files directly to **staff who have shared with them** or **the staff member who created their account**. Received files appear in your "My files" marked "Vendor upload: vendor email" and are virus-scanned.

---

# Part 2: External users

## 7. Receiving shared files (one-time share recipients)

1. You receive an invitation email saying someone shared files with you, containing the share link.
2. Open the link, enter **the email address the invitation was sent to**, and click "Send code".
3. Check your inbox, enter the 6-digit code and click "Verify".
   - The code is valid for 10 minutes, can be used once, and allows at most 5 attempts.
   - The screen always says "If you are on the recipient list, a code has been sent"; if no email arrives, check that the address is correct, or look in your spam folder.
4. After verification you see the list of shared files; verification lasts 1 hour, after which you must verify again.
   - **View**: watch in the browser, with page turning and zoom.
   - **Download**: shown only if the sender allows downloads.
   - Files that cannot be previewed online do not show "View".
   - When a download is refused you may see: "This file can't be downloaded with a tracking mark. Ask the sender for another format.", "This share is view-only.", "This file was blocked by the virus scan.", "This file could not be virus-scanned and is blocked.", "This file can't be opened here."

Things to know:

- Files may carry a watermark showing your email, the time, your IP and a tracking code. Downloaded files may also have the tracking code embedded, so do not pass them on freely.
- If you see "This share has expired or been revoked", "This share has reached its view limit", "Access from your network location is not allowed" or "Your email domain is not allowed to access this share", contact the person who shared with you; the last two are caused by the administrator's access policy (network location or email domain restrictions), not by a problem with your account.
- If a file shows "This file is currently unavailable (download is disabled by the administrator)", the administrator has stopped allowing downloads and this file cannot be viewed online. Contact the person who shared with you.
- If you see "The file is still being prepared or scanned, please try again shortly", the watermarked version is still being generated; wait a few minutes before downloading.
- When you are done, click "Leave".

## 8. Uploading files for an upload request

1. You receive an invitation email asking you to upload files.
2. Open the link, enter the email address the email was sent to, click "Send code", then enter the 6-digit code from the email and click "Verify".
3. The page shows the limits: allowed file types, how many more files you can upload, and the space left.
4. Drag files into the upload area, or click to choose files. You can pause and resume; after a disconnection, choose the same file again and the upload continues where it stopped.
5. "Your uploaded files" lists the files you have uploaded. You can see only your own files, not other uploaders' files.

Common messages:

| Message | Cause |
|---|---|
| This file type is not allowed | The extension is not on the allowed list (it may come from this request or from the administrator's site-wide rule). |
| File is too large | The file exceeds the per-file size limit set by this request or by the administrator. |
| The recipient's storage is full | The staff member receiving the files has used up their storage quota; contact them. |
| Access from your network location is not allowed | The administrator allows external users to connect only from certain networks; use an allowed network or contact the other party. |
| The file limit for this request has been reached | The request's file count is full. |
| Not enough space left for this file | The file is larger than the remaining space. |
| This upload request has expired or been revoked | Contact the person who asked you to upload. |
| This request does not accept any file types right now. Contact the requester. | The request currently has no file types that can be uploaded, so nothing can be uploaded. |

Uploaded files are virus-scanned, and the other party can open them only after they are confirmed clean.

## 9. Using a vendor account

### Activating your account (first time)

1. You receive an invitation email to activate your account; the link is valid for 7 days and can be used once.
2. Open the link; the page shows your account email and a QR code.
3. Scan the QR code with an authenticator app on your phone (for example Google Authenticator or Microsoft Authenticator).
4. Set a **password** (at least 12 characters) and enter it again to confirm.
5. Enter the 6-digit code shown in the authenticator app and click "Activate account".
6. When you see "Your account is active", **wait for the authenticator app to move to the next code**, then sign in on the login page. The code you just used cannot be reused.

If the page says "This invitation is no longer valid", the link has been used, has expired, or has been replaced by a newer invitation; ask whoever invited you to invite you again.

### Login

On the login page, enter your email and password, then the 6-digit code from your authenticator app. Vendor accounts must use two-factor authentication.

### Shared with me

After you sign in you land on "Shared with me", which lists everything shared with you: who shared it, the message, the expiry and the number of files. Click "Open" to see the files; you can view them online and, if downloads are allowed, download them. The administrator's access policy also applies to vendors: if you sign in from a network the administrator has not allowed, the system shows the same "Invalid email or password" message as for a wrong password (it does not mention the network restriction); use an allowed network or contact an administrator. You may also be unable to open shares, or see "This file is currently unavailable (download is disabled by the administrator)". As with one-time shares, files may carry a watermark with your email and a tracking code.

### Uploading files to staff

1. Click "Upload" at the top.
2. In "Recipient", choose who to send to. The list contains only staff who have shared files with you or who created your account; if the list is empty, ask them to share a file with you first.
3. After choosing a recipient, drag files into the upload area. Uploads can be paused and resumed.
   - You may see "This file type is not allowed", "File is too large" or "The recipient's storage is full", for the same reasons as in the common messages under [Uploading files for an upload request](#8-uploading-files-for-an-upload-request).
4. "Your uploads" lists the files you have sent and their recipients. Uploaded files are virus-scanned.

### Account expiry or deactivation

Accounts have an expiry date. Once expired or disabled, you cannot sign in, and sessions in use end immediately. To extend the account, contact the staff member who created it.

---

## 10. FAQ

**Q: I did not receive the invitation email or the code?**
Check your spam folder first. Code emails usually arrive within a minute. If there is still nothing, make sure the email you entered is exactly the address the invitation was sent to.

**Q: What if the connection drops halfway through an upload?**
Reopen the page and choose the same file; the system continues from where it stopped. For vendor uploads, choose the same recipient.

**Q: Why did the recipient get a PDF instead of a Word file?**
The share had both "Allow download" and "Watermark" turned on, so the system converts Office files into watermarked PDFs. If they need the original, turn the watermark off and share again.

**Q: A file from an outside person keeps showing "Scanning"?**
The antivirus service needs a few minutes to download its virus signatures after it starts. If it is still not done after half an hour, tell a system administrator.

**Q: I lost my phone and cannot get codes?**
Contact a system administrator for help.

**Q: Can a screenshot be traced?**
A screenshot carries no embedded mark, but the visible watermark on the screen contains the tracking code, which an administrator can use to look it up manually.
