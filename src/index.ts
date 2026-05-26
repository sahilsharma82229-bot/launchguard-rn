#!/usr/bin/env node
import fs from 'fs';
import path from 'path';
import { scanProject } from './scanner';
import { toMarkdown } from './report';

const target = process.argv[2] || process.cwd();
const outFlag = process.argv.findIndex((a: string) => a === '--out');
const out = outFlag >= 0 ? process.argv[outFlag + 1] : 'launchguard-report.md';

const result = scanProject(target);
const markdown = toMarkdown(result);
fs.writeFileSync(path.resolve(out), markdown);

console.log(`\nLaunchGuard RN score: ${result.score}/100`);
console.log(`Findings: ${result.findings.length}`);
console.log(`Report saved: ${out}\n`);
if (result.summary.critical > 0 || result.summary.high > 0) process.exitCode = 1;
