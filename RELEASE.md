# v2.1.0 — Firewall Improvements

This release fixes a bug that made permanent bans ineffective against web traffic, and makes the firewall page easier to use on servers with many rules.

## Upgrading

Update in the app as usual. The backup scripts are unchanged.

### Check your existing bans

UFW applies the **first** rule that matches. Before this release, "Ban IP" and "Deny" rules were added to the **end** of the list. If an `allow 80/tcp` or `allow 443/tcp` rule came earlier, a banned IP could still reach your websites once fail2ban's temporary ban had expired.

New bans are now placed at the top. Existing rules are not moved automatically. To check yours:

```bash
sudo ufw status numbered
```

If `DENY IN` rules for banned IPs appear **below** your `ALLOW` rules for 80/443, move them to the top. `ufw` skips a rule that already exists, so first delete the old rule, then add it again. You can do this on the Firewall page (delete the rule, then ban the IP again) or from the command line:

```bash
sudo ufw delete deny from 203.0.113.9
sudo ufw prepend deny from 203.0.113.9
```

## What's new

- **Search and paging for UFW rules.** Search by port, IP, action or comment, show only manual or only fail2ban rules, and choose 25/50/100 rules per page. The header shows how many rules match.
- **Lock-out protection.** The page asks for confirmation before:
  - deleting the last rule that lets clients reach your SSH port (checked separately for IPv4 and IPv6, and only when the default incoming policy is deny/reject),
  - adding a rule that denies the SSH port from anywhere,
  - banning the IP address you are connected from.
- **IPv6 bans.** The ban form now accepts IPv6 addresses.
- **Whitelist edits are marked as unsaved** until you press Save, and the page warns before you leave with unsaved changes.

## Fixes

- **Permanent bans and deny rules now take effect.** They are added with `ufw prepend`, so they come before any allow rule. Allow rules are still added at the end.
