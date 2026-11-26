# v2.3.1 — Ask Before Replacing Uploaded Files

Uploading a file whose name already exists in the folder, for example `index.php` in a live site, replaced the existing file without asking. The Files page now asks first.

## Upgrading

Update in the app as usual, then reload any open Files tab. A Files page that was opened before the update cannot overwrite existing files any more. It shows "already exists, not replaced" for them until you reload.

## What's new

**Ask before replacing.** Before an upload starts, the Files page checks which names already exist in the target folder, using the same filename cleanup as the upload itself. If any do, you get one question for the whole upload:

- **Replace** overwrites the existing files.
- **Skip** (or Esc) uploads only the new files and leaves the existing ones untouched.

**Enforced on the server.** An upload without that confirmation never overwrites a file. That includes a file that appears between the check and the upload. A folder with the same name is never replaced, and the audit log records whether a file was replaced.
