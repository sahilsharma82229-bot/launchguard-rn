# LaunchGuard RN

CLI tool to audit React Native and Expo apps for security risks, backend misconfigurations, crash risks, privacy gaps, and launch readiness.

![GitHub Actions](https://github.com/sahilsharma82229-bot/launchguard-rn/actions/workflows/ci.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![TypeScript](https://img.shields.io/badge/TypeScript-CLI-blue)
![React Native](https://img.shields.io/badge/React%20Native-Expo-green)

## Quick links

- [Example report](docs/example-report.md)
- [Roadmap](ROADMAP.md)
- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)

## What it checks

- Exposed secrets and API keys
- Firebase-related risk patterns
- Crash-prone code patterns
- Missing error handling
- Android permission concerns
- React Native / Expo project structure
- Package and dependency signals
- TypeScript project readiness
- Launch-readiness checklist gaps
- Basic security and safety issues

## Why this exists

Many mobile apps fail at launch because of small hidden problems:

- exposed keys
- unsafe Firebase setup
- missing loading/error states
- bad permissions
- crash risks
- incomplete release checks

LaunchGuard RN gives developers a simple report before they ship.

## Install locally

```bash
npm install
npm run build
````

## Usage

Scan the current folder:

```bash
node dist/index.js .
```

Scan another React Native or Expo app:

```bash
node dist/index.js C:/Users/yourname/Documents/my-expo-app
```

## Example output

```text
LaunchGuard RN Report

Score: 78/100

Warnings:
- Possible exposed API key found
- Android permissions should be reviewed
- Firebase config detected, verify security rules
- Missing production readiness checklist
```

## Example report

See a sample audit report here:

[Example LaunchGuard RN Report](docs/example-report.md)

## GitHub Actions

This repo includes a basic CI workflow to make sure the project builds successfully.

## Roadmap

* Better Firebase security audit
* Better Expo config checks
* JSON report output
* HTML report output
* GitHub Actions scanner mode
* More security rules
* More crash-risk detection
* AI fix-prompt generator
* Play Store readiness score
* Accessibility checks

## Who is this for?

* React Native developers
* Expo developers
* Indie app builders
* Student developers
* Small teams preparing for launch
* Developers who want a quick safety check before release

## Contributing

Contributions are welcome.

Good first issues:

* Add new scanner rule
* Improve report formatting
* Add Expo-specific checks
* Add Firebase rule examples
* Add test cases
* Improve documentation

## License

MIT
