# LaunchGuard RN

**Pre-launch safety scanner for React Native and Expo apps.**

LaunchGuard RN checks your app before release and generates a simple launch-readiness score with exact fix prompts for Codex, Claude, Cursor, or any AI coding agent.

## What it checks

- Hardcoded API keys and secrets
- Firebase rule risks
- Missing error boundaries
- Network calls without safe error handling
- Permission/privacy store-readiness issues
- Missing CI setup
- Missing README/project docs
- Crash-risk patterns
- Play Store readiness gaps
- Fix prompts for AI coding tools

## Install

```bash
npm install
npm run build
```

## Use locally

Scan the current folder:

```bash
npm run dev -- .
```

Scan another app:

```bash
npm run dev -- C:/Users/yourname/Documents/my-expo-app
```

Save report somewhere else:

```bash
npm run dev -- ./my-app --out ./report.md
```

## Future one-command usage

After publishing to npm:

```bash
npx launchguard-rn ./my-app
```

## Example output

```txt
LaunchGuard RN score: 72/100
Findings: 4
Report saved: launchguard-report.md
```

## Why this exists

Before launching an app, developers worry about crashes, exposed keys, Firebase mistakes, weak privacy setup, and app-store rejection. LaunchGuard RN gives a fast first-pass audit and fix plan.

It does **not** replace professional security review, manual QA, or real device testing.

## Roadmap

- Expo config audit
- AndroidManifest permission scanner
- Bundle size analyzer
- Unused assets detector
- Accessibility checks
- Navigation anti-pattern detector
- Offline readiness checker
- GitHub PR comment bot
- HTML report
- SARIF output for GitHub Security tab

## Contributing

Pull requests are welcome. Keep checks practical, explain why each issue matters, and include a fix prompt.

## License

MIT
