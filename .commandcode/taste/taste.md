# taste
- Use informal Indonesian mixed with English (casual style with "bro", "gw", "lu", "sip"). Confidence: 0.85

# testing
- Verify fixes actually resolve the originally reported issue end-to-end before declaring them as fixed — don't just test individual components and assume the problem is gone. Confidence: 0.65

# windows
- Use PowerShell-native commands (e.g., `Remove-Item -Recurse -Force` or `rm -Recurse -Force`) instead of Unix-style commands like `rm -rf` since the user is on Windows. Confidence: 0.70
- Use `;` as command separator in PowerShell instead of `&&` (e.g., `cd backend; python -c "..."`). Confidence: 0.65
- Prefix batch file execution with `.\` in PowerShell (e.g., `.\start_backend.bat` instead of `start_backend.bat`). Confidence: 0.65

# infrastructure
- Avoid using Docker for local development/setup because it consumes too many resources on their device. Confidence: 0.65

# communication
- Don't overstate visual/UI improvements — if changes are structural (refactoring, code organization) rather than visually apparent, be transparent about what actually changed vs what the user will see. Confidence: 0.78

# ui
- Ensure all pages have consistent layout/styling matching the dashboard — pages besides /dashboard should not look plain or lack layout structure. Confidence: 0.70

# ai-config
- Use a single custom AI provider configuration (base_url, api_key, model) instead of provider-specific configs — the system should auto-detect compatibility with OpenAI-compatible APIs. Confidence: 0.65
