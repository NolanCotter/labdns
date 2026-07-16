# Naming model

Names are lowercase DNS labels with invalid characters replaced by one hyphen and leading/trailing hyphens removed. The default collision policy is `suffix-host`; duplicate results are never silently changed. The engine uses a custom zone, defaulting to `home.arpa`.
