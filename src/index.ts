#!/usr/bin/env node
import fs from 'fs';
import path from 'path';
import { scanProject } from './scanner';
import { toMarkdown } from './report';

function printHelp() {
  console.log(`
LaunchGuard RN

Usage:
  launchguard-rn <project-path> [--out report.md]
  node dist/index.js <project-path> [--out report.md]

Examples:
  node dist/index.js .
  node dist/index.js C:/Users/yourname/Documents/my-expo-app
  node dist/index.js ./my-app --out ./launchguard-report.md
`);
}

const args = process.argv.slice(2);
if (args.includes('--help') || args.includes('-h')) {
  printHelp();
  process.exit(0);
}

const target = args.find(a => !a.startsWith('--')) || process.cwd();
const outFlag = args.findIndex(a => a === '--out');
const out = outFlag >= 0 ? args[outFlag + 1] : 'launchguard-report.md';

try {
  const result = scanProject(target);
  const markdown = toMarkdown(result);
  fs.writeFileSync(path.resolve(out), markdown);
  console.log(`\nLaunchGuard RN score: ${result.score}/100`);
  console.log(`Findings: ${result.findings.length}`);
  console.log(`Report saved: ${out}\n`);
  if (result.summary.critical > 0 || result.summary.high > 0) process.exitCode = 1;
} catch (error) {
  console.error(`\nLaunchGuard RN failed: ${(error as Error).message}\n`);
  printHelp();
  process.exit(1);
}
