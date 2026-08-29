"""Offline domain classification database.

Maps domain suffixes to (organization, PrivacyCategory).  Subdomain matching
is handled by ClassificationService — entries here use the registered domain
only (e.g. "google-analytics.com", not "www.google-analytics.com").

Source: manually curated from Disconnect.me, EasyList, and DuckDuckGo Tracker
Radar.  Version is bumped when the list is updated.
"""

from __future__ import annotations

from sentinel.domain.enums import PrivacyCategory

DATASET_VERSION = "1.0.0"

# (organization, PrivacyCategory)
_Entry = tuple[str, PrivacyCategory]

# Registered domain → (org, category)
DOMAIN_DB: dict[str, _Entry] = {
    # ── Analytics ─────────────────────────────────────────────────────────────
    "google-analytics.com": ("Google", PrivacyCategory.ANALYTICS),
    "analytics.google.com": ("Google", PrivacyCategory.ANALYTICS),
    "googletagmanager.com": ("Google", PrivacyCategory.ANALYTICS),
    "googletagservices.com": ("Google", PrivacyCategory.ANALYTICS),
    "googlesyndication.com": ("Google", PrivacyCategory.ADVERTISING),
    "doubleclick.net": ("Google", PrivacyCategory.ADVERTISING),
    "adservice.google.com": ("Google", PrivacyCategory.ADVERTISING),
    "segment.io": ("Segment", PrivacyCategory.ANALYTICS),
    "segment.com": ("Segment", PrivacyCategory.ANALYTICS),
    "amplitude.com": ("Amplitude", PrivacyCategory.ANALYTICS),
    "mixpanel.com": ("Mixpanel", PrivacyCategory.ANALYTICS),
    "heap.io": ("Heap", PrivacyCategory.ANALYTICS),
    "fullstory.com": ("FullStory", PrivacyCategory.ANALYTICS),
    "loggly.com": ("Loggly", PrivacyCategory.ANALYTICS),
    "hotjar.com": ("Hotjar", PrivacyCategory.ANALYTICS),
    "mouseflow.com": ("Mouseflow", PrivacyCategory.ANALYTICS),
    "smartlook.com": ("Smartlook", PrivacyCategory.ANALYTICS),
    "clarity.ms": ("Microsoft", PrivacyCategory.ANALYTICS),
    "app-measurement.com": ("Google", PrivacyCategory.ANALYTICS),
    "firebase.com": ("Google", PrivacyCategory.ANALYTICS),
    "firebaseapp.com": ("Google", PrivacyCategory.ANALYTICS),
    "crashlytics.com": ("Google", PrivacyCategory.TELEMETRY),
    # ── Advertising ───────────────────────────────────────────────────────────
    "facebook.com": ("Meta", PrivacyCategory.ADVERTISING),
    "facebook.net": ("Meta", PrivacyCategory.ADVERTISING),
    "fbcdn.net": ("Meta", PrivacyCategory.CDN),
    "connect.facebook.net": ("Meta", PrivacyCategory.TRACKING),
    "ads.twitter.com": ("Twitter/X", PrivacyCategory.ADVERTISING),
    "analytics.twitter.com": ("Twitter/X", PrivacyCategory.ANALYTICS),
    "snap.com": ("Snap", PrivacyCategory.ADVERTISING),
    "sc-static.net": ("Snap", PrivacyCategory.ADVERTISING),
    "snapchat.com": ("Snap", PrivacyCategory.SOCIAL),
    "criteo.com": ("Criteo", PrivacyCategory.ADVERTISING),
    "criteo.net": ("Criteo", PrivacyCategory.ADVERTISING),
    "taboola.com": ("Taboola", PrivacyCategory.ADVERTISING),
    "outbrain.com": ("Outbrain", PrivacyCategory.ADVERTISING),
    "adnxs.com": ("Xandr", PrivacyCategory.ADVERTISING),
    "rubiconproject.com": ("Magnite", PrivacyCategory.ADVERTISING),
    "pubmatic.com": ("PubMatic", PrivacyCategory.ADVERTISING),
    "openx.net": ("OpenX", PrivacyCategory.ADVERTISING),
    "33across.com": ("33Across", PrivacyCategory.ADVERTISING),
    "moatads.com": ("Oracle", PrivacyCategory.ADVERTISING),
    "scorecardresearch.com": ("Comscore", PrivacyCategory.ANALYTICS),
    "chartbeat.com": ("Chartbeat", PrivacyCategory.ANALYTICS),
    "quantcast.com": ("Quantcast", PrivacyCategory.ANALYTICS),
    "adsymptotic.com": ("Amazon", PrivacyCategory.ADVERTISING),
    "amazon-adsystem.com": ("Amazon", PrivacyCategory.ADVERTISING),
    # ── Tracking / fingerprinting ─────────────────────────────────────────────
    "newrelic.com": ("New Relic", PrivacyCategory.TELEMETRY),
    "nr-data.net": ("New Relic", PrivacyCategory.TELEMETRY),
    "sentry.io": ("Sentry", PrivacyCategory.TELEMETRY),
    "bugsnag.com": ("Bugsnag", PrivacyCategory.TELEMETRY),
    "rollbar.com": ("Rollbar", PrivacyCategory.TELEMETRY),
    "raygun.io": ("Raygun", PrivacyCategory.TELEMETRY),
    "datadoghq.com": ("Datadog", PrivacyCategory.TELEMETRY),
    "appsflyer.com": ("AppsFlyer", PrivacyCategory.TRACKING),
    "branch.io": ("Branch", PrivacyCategory.TRACKING),
    "adjust.com": ("Adjust", PrivacyCategory.TRACKING),
    "kochava.com": ("Kochava", PrivacyCategory.TRACKING),
    "singular.net": ("Singular", PrivacyCategory.TRACKING),
    "mparticle.com": ("mParticle", PrivacyCategory.TRACKING),
    "onesignal.com": ("OneSignal", PrivacyCategory.TRACKING),
    "intercom.io": ("Intercom", PrivacyCategory.FIRST_PARTY),
    "intercom.com": ("Intercom", PrivacyCategory.FIRST_PARTY),
    # ── Telemetry (OS / app telemetry) ────────────────────────────────────────
    "apple.com": ("Apple", PrivacyCategory.FIRST_PARTY),
    "icloud.com": ("Apple", PrivacyCategory.FIRST_PARTY),
    "apple-relay.com": ("Apple", PrivacyCategory.FIRST_PARTY),
    "ls.apple.com": ("Apple", PrivacyCategory.TELEMETRY),
    "xp.apple.com": ("Apple", PrivacyCategory.TELEMETRY),
    "telemetry.microsoft.com": ("Microsoft", PrivacyCategory.TELEMETRY),
    "vortex.data.microsoft.com": ("Microsoft", PrivacyCategory.TELEMETRY),
    "watson.telemetry.microsoft.com": ("Microsoft", PrivacyCategory.TELEMETRY),
    "settings-win.data.microsoft.com": ("Microsoft", PrivacyCategory.TELEMETRY),
    "google.com": ("Google", PrivacyCategory.FIRST_PARTY),
    "googleapis.com": ("Google", PrivacyCategory.CLOUD_API),
    "gstatic.com": ("Google", PrivacyCategory.CDN),
    "youtube.com": ("Google", PrivacyCategory.FIRST_PARTY),
    # ── CDN ───────────────────────────────────────────────────────────────────
    "akamai.net": ("Akamai", PrivacyCategory.CDN),
    "akamaitech.net": ("Akamai", PrivacyCategory.CDN),
    "akamaiedge.net": ("Akamai", PrivacyCategory.CDN),
    "akamaihd.net": ("Akamai", PrivacyCategory.CDN),
    "cloudflare.com": ("Cloudflare", PrivacyCategory.CDN),
    "cloudflare.net": ("Cloudflare", PrivacyCategory.CDN),
    "fastly.net": ("Fastly", PrivacyCategory.CDN),
    "fastlylb.net": ("Fastly", PrivacyCategory.CDN),
    "jsdelivr.net": ("jsDelivr", PrivacyCategory.CDN),
    "unpkg.com": ("unpkg", PrivacyCategory.CDN),
    "bootstrapcdn.com": ("StackPath", PrivacyCategory.CDN),
    "cloudfront.net": ("Amazon", PrivacyCategory.CDN),
    # ── Cloud APIs ────────────────────────────────────────────────────────────
    "amazonaws.com": ("Amazon", PrivacyCategory.CLOUD_API),
    "awsstatic.com": ("Amazon", PrivacyCategory.CDN),
    "azure.com": ("Microsoft", PrivacyCategory.CLOUD_API),
    "azureedge.net": ("Microsoft", PrivacyCategory.CDN),
    "windows.net": ("Microsoft", PrivacyCategory.CLOUD_API),
    # ── Social ────────────────────────────────────────────────────────────────
    "twitter.com": ("Twitter/X", PrivacyCategory.SOCIAL),
    "t.co": ("Twitter/X", PrivacyCategory.SOCIAL),
    "instagram.com": ("Meta", PrivacyCategory.SOCIAL),
    "linkedin.com": ("LinkedIn", PrivacyCategory.SOCIAL),
    "linkedin.net": ("LinkedIn", PrivacyCategory.CDN),
    "pinterest.com": ("Pinterest", PrivacyCategory.SOCIAL),
    "reddit.com": ("Reddit", PrivacyCategory.SOCIAL),
    "tiktok.com": ("TikTok", PrivacyCategory.SOCIAL),
    "tiktokcdn.com": ("TikTok", PrivacyCategory.CDN),
    "byteoversea.com": ("TikTok", PrivacyCategory.TRACKING),
    "muscdn.com": ("TikTok", PrivacyCategory.CDN),
}
