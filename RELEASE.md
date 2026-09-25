# v2.1.1 — New App Icon

A new app icon for the installed app (PWA), the browser tab and notifications. Nothing else changed.

## Upgrading

Update in the app as usual. The backup scripts are unchanged.

## What's new

- **New app icon** in every format the platforms need:
  - a standard icon with transparent corners;
  - a separate **maskable** version for Android. It fills the whole shape and keeps the symbol inside the safe zone, so launchers can apply any mask shape without cutting anything off;
  - an **Apple touch icon** for the iOS home screen;
  - new **favicons** (32 and 16 px) for the browser tab, replacing the SVG favicon.
- **Notification badge fixed on Android.** Android draws the small status-bar badge as a single-colour silhouette. The full-colour icon therefore showed up as a plain white square. There is now a dedicated silhouette badge.
- Icon URLs in the manifest change only when an icon file actually changes. An installed app picks up a new icon once and is not asked again on every release. The earlier maskable problem (repeated "update icon" prompts, fixed in v1.7.4) came from reusing the standard icon, and that no longer happens.

## After updating

- **Android:** the installed app asks once whether to use the new icon.
- **iPhone/iPad:** iOS never updates a home-screen icon by itself. Remove VPS Manager from the home screen and add it again via *Share → Add to Home Screen*.
- **Browser tab:** shows the new favicon straight away.
