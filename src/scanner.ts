import fs from 'fs';
import path from 'path';
import { rules, FileRecord, RuleContext } from './rules';
import { ScanResult, Severity } from './types';

const SKIP = new Set(['node_modules', '.git', 'dist', 'build', '.expo', 'android/app/build', 'ios/build', 'coverage', '.next']);
const ALLOWED = ['.ts', '.tsx', '.js', '.jsx', '.json', '.md', '.rules', '.xml', '.gradle', '.plist', '.env', '.yml', '.yaml', '.sql', '.graphql', '.gql'];

function walk(dir: string, root: string, out: FileRecord[] = []): FileRecord[] {
  if (!fs.existsSync(dir)) throw new Error(`Project path not found: ${dir}`);
  for (const item of fs.readdirSync(dir)) {
    const full = path.join(dir, item);
    const rel = path.relative(root, full);
    if ([...SKIP].some(s => rel === s || rel.startsWith(s + path.sep))) continue;
    const stat = fs.statSync(full);
    if (stat.isDirectory()) walk(full, root, out);
    else if (stat.size < 500_000 && ALLOWED.some(ext => item.endsWith(ext) || item === ext)) {
      try { out.push({ path: rel, content: fs.readFileSync(full, 'utf8') }); } catch {}
    }
  }
  return out;
}

function scoreFrom(findings: ScanResult['findings']): number {
  const weight: Record<Severity, number> = { critical: 25, high: 15, medium: 8, low: 3, info: 0 };
  return Math.max(0, 100 - findings.reduce((sum, f) => sum + weight[f.severity], 0));
}

export function scanProject(projectPath: string): ScanResult {
  const root = path.resolve(projectPath);
  const files = walk(root, root);
  const names = new Set(files.map(f => f.path.replace(/\\/g, '/')));
  const ctx: RuleContext = {
    files,
    hasFile: (name) => names.has(name),
    findFiles: (pattern) => files.filter(f => pattern.test(f.path.replace(/\\/g, '/')) || pattern.test(f.content))
  };
  const seen = new Set<string>();
  const findings = rules.flatMap(rule => rule(ctx)).filter(f => {
    const key = `${f.id}:${f.file || ''}:${f.evidence || ''}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>;
  for (const f of findings) summary[f.severity]++;
  return { projectPath: root, score: scoreFrom(findings), findings, summary, generatedAt: new Date().toISOString() };
}
