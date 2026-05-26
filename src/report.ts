import { ScanResult } from './types';

export function toMarkdown(result: ScanResult): string {
  const lines = [
    '# LaunchGuard RN Report', '',
    `**Project:** ${result.projectPath}`,
    `**Generated:** ${result.generatedAt}`,
    `**Launch Readiness Score:** ${result.score}/100`, '',
    '## Summary', '',
    `- Critical: ${result.summary.critical}`,
    `- High: ${result.summary.high}`,
    `- Medium: ${result.summary.medium}`,
    `- Low: ${result.summary.low}`, '',
    '## Findings', ''
  ];

  if (result.findings.length === 0) lines.push('No major issues found. Still test manually before launch.');

  result.findings.forEach((f, i) => {
    lines.push(`### ${i + 1}. ${f.title}`);
    lines.push(`**Severity:** ${f.severity}`);
    if (f.file) lines.push(`**File:** ${f.file}`);
    if (f.evidence) lines.push(`**Evidence:** \`${f.evidence}\``);
    lines.push(`**Why it matters:** ${f.whyItMatters}`);
    lines.push(`**Fix:** ${f.fix}`);
    lines.push('**Codex / Claude / Cursor Prompt:**');
    lines.push('```');
    lines.push(f.codexPrompt);
    lines.push('```', '');
  });

  return lines.join('\n');
}
