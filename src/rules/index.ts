import { Finding } from '../types';

export interface FileRecord { path: string; content: string }
export interface RuleContext { files: FileRecord[]; hasFile: (name: string) => boolean }
export type Rule = (ctx: RuleContext) => Finding[];

const secretPatterns = [
  /AIza[0-9A-Za-z\-_]{20,}/g,
  /sk-[A-Za-z0-9]{20,}/g,
  /AKIA[0-9A-Z]{16}/g,
  /password\s*[:=]\s*['\"][^'\"]+['\"]/gi,
  /secret\s*[:=]\s*['\"][^'\"]+['\"]/gi,
];

export const rules: Rule[] = [
  ({ files }) => {
    const findings: Finding[] = [];
    for (const f of files) {
      for (const p of secretPatterns) {
        const match = f.content.match(p);
        if (match) findings.push({
          id: 'secret-leak', title: 'Possible hardcoded secret/API key', severity: 'critical', file: f.path,
          evidence: match[0].slice(0, 28) + '…',
          whyItMatters: 'Hardcoded secrets can be copied from public repos or app bundles.',
          fix: 'Move secrets to backend, CI secrets, Firebase Remote Config, or secure environment handling. Rotate exposed keys.',
          codexPrompt: 'Scan this repo for hardcoded secrets/API keys. Move them to safe configuration, add .env examples, and ensure no real secret is committed.'
        });
      }
    }
    return findings;
  },
  ({ files }) => files.some(f => /firebase/i.test(f.content)) && !files.some(f => /rules_version|allow read|allow write/.test(f.content)) ? [{
    id: 'firebase-rules-missing', title: 'Firebase detected but rules file not found', severity: 'high',
    whyItMatters: 'Weak or missing Firestore/Storage rules can expose user data.',
    fix: 'Add and review firestore.rules/storage.rules. Deny by default and allow only owner-scoped access.',
    codexPrompt: 'Audit Firebase usage and create secure Firestore/Storage rules with deny-by-default, auth checks, and owner-scoped document access.'
  }] : [],
  ({ files }) => !files.some(f => /ErrorBoundary|componentDidCatch|getDerivedStateFromError/.test(f.content)) ? [{
    id: 'missing-error-boundary', title: 'No React error boundary found', severity: 'medium',
    whyItMatters: 'Uncaught UI errors can crash screens and hurt retention.',
    fix: 'Add a global ErrorBoundary around app navigation and log recoverable errors.',
    codexPrompt: 'Add a production-safe ErrorBoundary to this React Native app without changing existing navigation or features.'
  }] : [],
  ({ files }) => files.some(f => /fetch\(|axios\./.test(f.content)) && !files.some(f => /catch\(|try\s*{/.test(f.content)) ? [{
    id: 'network-error-handling', title: 'Network calls may lack error handling', severity: 'medium',
    whyItMatters: 'Failed requests without loading/error states create broken UX.',
    fix: 'Wrap API calls with try/catch, timeout handling, retries where safe, and user-friendly messages.',
    codexPrompt: 'Find all network calls and add safe loading, timeout, error, and retry handling without removing features.'
  }] : [],
  ({ files }) => files.some(f => /requestPermissions|PermissionsAndroid|expo-location|expo-camera/.test(f.content)) && !files.some(f => /privacy|permission.*reason|NSCameraUsageDescription|NSLocationWhenInUseUsageDescription/i.test(f.content)) ? [{
    id: 'permission-rationale-missing', title: 'Permissions used without clear privacy rationale', severity: 'high',
    whyItMatters: 'App stores may reject apps that request permissions without clear explanation.',
    fix: 'Add permission purpose strings and in-app explanations before asking users.',
    codexPrompt: 'Audit Android/iOS permissions and add clear user-facing rationales and store-compliant permission descriptions.'
  }] : [],
  ({ hasFile }) => !hasFile('README.md') ? [{
    id: 'readme-missing', title: 'README missing', severity: 'low',
    whyItMatters: 'A public repo without a strong README gets fewer users and contributors.',
    fix: 'Add install steps, screenshots, demo, roadmap, and contribution guide.',
    codexPrompt: 'Create a polished open-source README with demo, install, usage, roadmap, and contribution sections.'
  }] : [],
  ({ hasFile }) => !hasFile('.github/workflows/ci.yml') ? [{
    id: 'ci-missing', title: 'GitHub Actions CI missing', severity: 'medium',
    whyItMatters: 'Without CI, broken code can enter main branch unnoticed.',
    fix: 'Add CI to run install, TypeScript check, lint, and tests on every PR.',
    codexPrompt: 'Add GitHub Actions CI for npm install, TypeScript check, lint, tests, and build.'
  }] : []
];
