import { Finding, Severity } from '../types';

export interface FileRecord { path: string; content: string }
export interface RuleContext { files: FileRecord[]; hasFile: (name: string) => boolean; findFiles: (pattern: RegExp) => FileRecord[] }
export type Rule = (ctx: RuleContext) => Finding[];

type RuleInput = Omit<Finding, 'severity'> & { severity?: Severity };

function finding(input: RuleInput): Finding {
  return { severity: 'medium', ...input };
}

function any(files: FileRecord[], pattern: RegExp): boolean {
  return files.some(f => pattern.test(f.content) || pattern.test(f.path.replace(/\\/g, '/')));
}

function matching(files: FileRecord[], pattern: RegExp): FileRecord[] {
  return files.filter(f => pattern.test(f.content) || pattern.test(f.path.replace(/\\/g, '/')));
}

function firstEvidence(content: string, pattern: RegExp): string | undefined {
  const match = content.match(pattern);
  return match ? match[0].slice(0, 90).replace(/\n/g, ' ') + (match[0].length > 90 ? '…' : '') : undefined;
}

const secretPatterns: Array<{ id: string; title: string; pattern: RegExp; severity: Severity; fix: string }> = [
  { id: 'google-api-key', title: 'Possible Google/Firebase API key found', pattern: /AIza[0-9A-Za-z\-_]{20,}/g, severity: 'high', fix: 'Restrict the key by app/package/domain/API, rotate if public, and never use it as a server secret.' },
  { id: 'openai-key', title: 'Possible OpenAI API key found', pattern: /sk-[A-Za-z0-9_\-]{20,}/g, severity: 'critical', fix: 'Rotate the key immediately and move model calls behind a backend or secure serverless function.' },
  { id: 'aws-access-key', title: 'Possible AWS access key found', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'critical', fix: 'Rotate the AWS key, remove it from Git history, and use server-side credentials only.' },
  { id: 'supabase-service-role', title: 'Possible Supabase service_role key found', pattern: /service_role|SUPABASE_SERVICE_ROLE|supabase_service_role/gi, severity: 'critical', fix: 'Never ship service_role keys in a mobile app. Keep them only on trusted backend/serverless code.' },
  { id: 'jwt-token', title: 'Possible hardcoded JWT/token found', pattern: /eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/g, severity: 'critical', fix: 'Remove hardcoded tokens, rotate them, and use short-lived user sessions.' },
  { id: 'generic-secret', title: 'Possible hardcoded password/secret', pattern: /(password|passwd|pwd|secret|token|private_key)\s*[:=]\s*['\"][^'\"]{8,}['\"]/gi, severity: 'critical', fix: 'Move secrets to environment variables, backend secrets, or CI secret storage. Rotate exposed values.' },
  { id: 'db-url', title: 'Possible database connection URL found', pattern: /(mongodb(\+srv)?:\/\/|postgres(ql)?:\/\/|mysql:\/\/)[^\s'\"]+/gi, severity: 'critical', fix: 'Never connect directly to production databases from mobile apps. Use a backend API and rotate leaked credentials.' }
];

export const rules: Rule[] = [
  // Secrets
  ({ files }) => {
    const findings: Finding[] = [];
    for (const f of files) {
      if (/\.env(\.|$)/i.test(f.path) && !/\.env\.example$/i.test(f.path)) {
        findings.push(finding({
          id: 'env-file-present', title: 'Environment file found in scan', severity: 'high', file: f.path,
          whyItMatters: 'Real .env files often contain private keys, backend URLs, database URLs, or tokens.',
          fix: 'Ensure .env files are gitignored. Commit only .env.example with fake values.',
          codexPrompt: 'Check .gitignore and repository history for real .env files. Keep only .env.example with placeholder values.'
        }));
      }
      for (const rule of secretPatterns) {
        const evidence = firstEvidence(f.content, rule.pattern);
        if (evidence) findings.push(finding({
          id: rule.id, title: rule.title, severity: rule.severity, file: f.path, evidence,
          whyItMatters: 'Secrets in a mobile app or public repo can be extracted and abused by attackers.',
          fix: rule.fix,
          codexPrompt: `Scan the project for ${rule.title}. Remove real secrets, add safe placeholders, update .gitignore, and document secure setup.`
        }));
      }
    }
    return findings;
  },

  // Backend/database scanners
  ({ files }) => any(files, /firebase|firestore|@react-native-firebase|firebase\/app/i) && !any(files, /rules_version|firestore\.rules|storage\.rules|allow\s+(read|write)/i) ? [finding({
    id: 'firebase-rules-missing', title: 'Firebase detected but security rules were not found', severity: 'high',
    whyItMatters: 'Weak Firestore/Storage rules can expose private user data or allow unauthorized writes.',
    fix: 'Add Firestore and Storage rules with deny-by-default, auth checks, ownership checks, and tests.',
    codexPrompt: 'Audit Firebase usage. Add secure firestore.rules and storage.rules using deny-by-default, request.auth checks, owner-scoped access, validation, and tests.'
  })] : [],

  ({ files }) => any(files, /allow\s+(read|write)\s*:\s*if\s*true|allow\s+read\s*,\s*write\s*:\s*if\s*true/i) ? [finding({
    id: 'firebase-open-rules', title: 'Firebase rules may allow public read/write', severity: 'critical',
    whyItMatters: 'Public read/write rules can leak or destroy user data.',
    fix: 'Replace public rules with authenticated, owner-scoped, validated rules.',
    codexPrompt: 'Find Firebase rules that allow public access. Replace with secure deny-by-default rules and owner-scoped access.'
  })] : [],

  ({ files }) => any(files, /supabase-js|createClient\(|SUPABASE_URL|SUPABASE_ANON/i) && !any(files, /row level security|RLS|enable row level security|policy/i) ? [finding({
    id: 'supabase-rls-check-missing', title: 'Supabase detected but RLS/policy evidence not found', severity: 'high',
    whyItMatters: 'Supabase projects need Row Level Security and policies to prevent cross-user data leaks.',
    fix: 'Enable RLS on every user-data table and create least-privilege policies.',
    codexPrompt: 'Audit Supabase usage. Add a checklist and SQL examples for enabling RLS, owner-scoped policies, safe anon key usage, and public bucket review.'
  })] : [],

  ({ files }) => any(files, /storage\.from\(|public\s*:\s*true|createBucket|bucket/i) && any(files, /supabase|appwrite|firebase/i) ? [finding({
    id: 'storage-bucket-review', title: 'Storage bucket permissions should be reviewed', severity: 'medium',
    whyItMatters: 'Public buckets or broad upload permissions can leak user files or allow abuse.',
    fix: 'Limit bucket read/write access, validate MIME type and file size, and use signed URLs when needed.',
    codexPrompt: 'Review all storage buckets. Add file size limits, MIME validation, owner-based access, signed URLs where needed, and safe upload error handling.'
  })] : [],

  ({ files }) => any(files, /appwrite|Client\(\)\.setEndpoint|APPWRITE/i) && !any(files, /permission|role\(|read\(|write\(|collection.*permission/i) ? [finding({
    id: 'appwrite-permissions-missing', title: 'Appwrite detected but permission evidence not found', severity: 'high',
    whyItMatters: 'Appwrite collections and buckets need explicit permissions to protect user data.',
    fix: 'Review database, collection, document, bucket, and function permissions.',
    codexPrompt: 'Audit Appwrite setup for collection permissions, bucket permissions, anonymous access, and function secrets.'
  })] : [],

  ({ files }) => any(files, /prisma|DATABASE_URL|schema\.prisma/i) ? [finding({
    id: 'prisma-database-review', title: 'Prisma/database backend detected; verify server-only usage', severity: 'high',
    whyItMatters: 'Database clients and DATABASE_URL must not be bundled into a mobile app.',
    fix: 'Keep Prisma and database access only on backend/serverless code. Mobile should call authenticated APIs.',
    codexPrompt: 'Verify Prisma/DATABASE_URL is server-only and cannot be bundled into React Native. Move database access behind secure API endpoints.'
  })] : [],

  ({ files }) => any(files, /graphql|ApolloClient|urql|gql`/i) && !any(files, /authorization|Bearer|authLink|setContext|x-hasura-admin-secret/i) ? [finding({
    id: 'graphql-auth-review', title: 'GraphQL detected; auth/header checks should be reviewed', severity: 'medium',
    whyItMatters: 'GraphQL endpoints without proper auth can expose large amounts of data quickly.',
    fix: 'Ensure auth headers, authorization checks, rate limits, and production introspection settings are correct.',
    codexPrompt: 'Audit GraphQL client usage for auth headers, token refresh, admin secret exposure, introspection risk, and overfetching.'
  })] : [],

  // Network/API safety
  ({ files }) => any(files, /http:\/\//i) ? [finding({
    id: 'insecure-http-url', title: 'Insecure HTTP URL found', severity: 'high',
    whyItMatters: 'Plain HTTP can expose tokens and user data to interception.',
    fix: 'Use HTTPS for all production API, image, and web URLs.',
    codexPrompt: 'Find all http:// URLs. Replace production endpoints with https:// or justify safe local-only development usage.'
  })] : [],

  ({ files }) => any(files, /fetch\(|axios\./) && !any(files, /AbortController|timeout|CancelToken|signal:/i) ? [finding({
    id: 'network-timeout-missing', title: 'Network calls may not have timeout handling', severity: 'medium',
    whyItMatters: 'Requests that hang forever create frozen screens and poor retention on slow networks.',
    fix: 'Add timeout/cancellation handling and user-friendly retry states.',
    codexPrompt: 'Add safe timeout and cancellation handling for fetch/axios calls without changing app behavior.'
  })] : [],

  ({ files }) => any(files, /fetch\(|axios\./) && !any(files, /catch\(|try\s*{|\.finally\(/) ? [finding({
    id: 'network-error-handling', title: 'Network calls may lack error handling', severity: 'medium',
    whyItMatters: 'Failed requests without loading/error states create broken UX.',
    fix: 'Wrap API calls with try/catch, timeout handling, retry where safe, and user-friendly messages.',
    codexPrompt: 'Find all network calls and add safe loading, timeout, error, and retry handling without removing features.'
  })] : [],

  ({ files }) => any(files, /refreshToken|accessToken|Bearer/i) && !any(files, /401|refresh.*token|interceptor|signOut|logout/i) ? [finding({
    id: 'token-refresh-review', title: 'Auth token handling should be reviewed', severity: 'medium',
    whyItMatters: 'Expired tokens can break sessions or cause unsafe retry loops.',
    fix: 'Handle 401 responses, refresh tokens safely, and log users out when refresh fails.',
    codexPrompt: 'Audit auth token handling for expiry, refresh, 401 handling, secure storage, and logout fallback.'
  })] : [],

  // Crash/stability
  ({ files }) => !any(files, /ErrorBoundary|componentDidCatch|getDerivedStateFromError|react-error-boundary/) ? [finding({
    id: 'missing-error-boundary', title: 'No React error boundary found', severity: 'medium',
    whyItMatters: 'Uncaught UI errors can crash screens and hurt retention.',
    fix: 'Add a global ErrorBoundary around app navigation and log recoverable errors.',
    codexPrompt: 'Add a production-safe ErrorBoundary to this React Native app without changing existing navigation or features.'
  })] : [],

  ({ files }) => !any(files, /Sentry|Crashlytics|Bugsnag|LogRocket|captureException|recordError/i) ? [finding({
    id: 'crash-reporting-missing', title: 'Crash reporting not detected', severity: 'high',
    whyItMatters: 'Without crash reporting, production crashes remain invisible after launch.',
    fix: 'Add Sentry, Firebase Crashlytics, Bugsnag, or another crash monitoring tool.',
    codexPrompt: 'Add a production crash reporting plan with safe user privacy settings, source maps, and error boundary integration.'
  })] : [],

  ({ files }) => any(files, /setInterval|setTimeout|addEventListener|watchPosition/i) && !any(files, /clearInterval|clearTimeout|removeEventListener|unsubscribe|remove\(\)/i) ? [finding({
    id: 'cleanup-risk', title: 'Possible missing cleanup for timers/listeners/subscriptions', severity: 'medium',
    whyItMatters: 'Uncleaned listeners and timers can cause memory leaks, battery drain, and duplicate actions.',
    fix: 'Return cleanup functions from effects and unsubscribe listeners on unmount.',
    codexPrompt: 'Find timers, subscriptions, and event listeners. Add proper cleanup in useEffect and component unmount paths.'
  })] : [],

  ({ files }) => any(files, /async\s+function|await\s+|\.then\(/) && !any(files, /unhandledRejection|try\s*{|catch\(/i) ? [finding({
    id: 'promise-error-risk', title: 'Async operations may lack rejection handling', severity: 'medium',
    whyItMatters: 'Unhandled promises can crash flows or silently break important features.',
    fix: 'Add try/catch and safe error reporting for async operations.',
    codexPrompt: 'Audit async operations and add rejection handling, user feedback, and logging where needed.'
  })] : [],

  // Privacy/compliance
  ({ files, hasFile }) => !hasFile('PRIVACY.md') && !any(files, /privacy policy|PrivacyPolicy|privacyUrl/i) ? [finding({
    id: 'privacy-policy-missing', title: 'Privacy policy evidence not found', severity: 'high',
    whyItMatters: 'Apps collecting user data usually need a privacy policy for app stores and user trust.',
    fix: 'Add a privacy policy URL/document and link it in the app/store listing.',
    codexPrompt: 'Add a privacy policy checklist covering collected data, purpose, retention, deletion, analytics, ads, and contact details.'
  })] : [],

  ({ files }) => any(files, /analytics|amplitude|mixpanel|segment|posthog|firebase analytics|logEvent/i) && !any(files, /consent|opt.?out|tracking transparency|ATT|analytics.*disabled/i) ? [finding({
    id: 'analytics-consent-review', title: 'Analytics detected; consent/privacy controls should be reviewed', severity: 'medium',
    whyItMatters: 'Analytics can create privacy and app-store disclosure obligations.',
    fix: 'Provide privacy disclosures, disable sensitive event logging, and add opt-out/consent if needed.',
    codexPrompt: 'Audit analytics usage for sensitive data, privacy disclosures, opt-out/consent, and Play Store/App Store data safety alignment.'
  })] : [],

  ({ files }) => any(files, /deleteAccount|account deletion|remove account/i) ? [] : [finding({
    id: 'account-deletion-check', title: 'Account deletion flow not detected', severity: 'medium',
    whyItMatters: 'Many apps need a clear way for users to delete accounts and associated data.',
    fix: 'Add account deletion flow, backend deletion path, and privacy policy instructions.',
    codexPrompt: 'Add or document account deletion flow, data deletion behavior, re-authentication, and backend cleanup.'
  })],

  ({ files }) => any(files, /AsyncStorage|SecureStore|MMKV|localStorage/i) && any(files, /token|password|secret|email|phone|health|location/i) && !any(files, /SecureStore|Keychain|Keystore|encrypted/i) ? [finding({
    id: 'sensitive-local-storage', title: 'Sensitive data may be stored without secure storage', severity: 'high',
    whyItMatters: 'Tokens and personal data should not be stored in plain local storage.',
    fix: 'Use SecureStore/Keychain/Keystore for sensitive values and minimize local retention.',
    codexPrompt: 'Audit local storage usage. Move sensitive tokens or personal data to secure storage and remove unnecessary persistence.'
  })] : [],

  // Store readiness and permissions
  ({ files }) => any(files, /PermissionsAndroid|requestPermissions|expo-location|expo-camera|expo-contacts|expo-notifications|RECORD_AUDIO|CAMERA|ACCESS_FINE_LOCATION/i) && !any(files, /NSCameraUsageDescription|NSLocationWhenInUseUsageDescription|NSMicrophoneUsageDescription|permission.*reason|permission.*rationale/i) ? [finding({
    id: 'permission-rationale-missing', title: 'Permissions used without clear rationale evidence', severity: 'high',
    whyItMatters: 'App stores may reject apps that request permissions without clear explanation.',
    fix: 'Add permission purpose strings and in-app explanations before asking users.',
    codexPrompt: 'Audit Android/iOS permissions and add clear user-facing rationales and store-compliant permission descriptions.'
  })] : [],

  ({ files }) => any(files, /expo-notifications|PushNotification|messaging\(\)|FCM|APNs/i) && !any(files, /notification.*settings|unsubscribe|disable notifications|opt.?out/i) ? [finding({
    id: 'push-notification-controls', title: 'Push notifications need user controls', severity: 'medium',
    whyItMatters: 'Notification abuse increases uninstalls and can violate platform expectations.',
    fix: 'Ask permission at the right time and provide notification settings/opt-out controls.',
    codexPrompt: 'Review push notification flow. Add permission timing, opt-out controls, category preferences, and safe token cleanup.'
  })] : [],

  ({ files }) => any(files, /targetSdkVersion|minSdkVersion|compileSdkVersion/i) ? [] : [finding({
    id: 'android-sdk-check', title: 'Android SDK/version config not detected', severity: 'low',
    whyItMatters: 'Outdated target SDK or missing versioning can block Play Store release.',
    fix: 'Verify targetSdkVersion, versionCode, versionName, package name, and signing config.',
    codexPrompt: 'Check Android/Expo release config for target SDK, app versioning, package name, signing, and Play Store readiness.'
  })],

  // UX/accessibility/responsiveness
  ({ files }) => any(files, /<Image|Image\s*source|backgroundImage/i) && !any(files, /defaultSource|onError|placeholder|fallback/i) ? [finding({
    id: 'image-fallback-missing', title: 'Images may not have fallback handling', severity: 'low',
    whyItMatters: 'Broken images make the app look unfinished and can harm trust.',
    fix: 'Add placeholders, onError fallback, skeleton states, and retry where needed.',
    codexPrompt: 'Find all remote images and add placeholder, loading, and fallback behavior without changing layout.'
  })] : [],

  ({ files }) => any(files, /Touchable|Pressable|Button|TextInput/i) && !any(files, /accessibilityLabel|accessibilityRole|accessibilityHint/i) ? [finding({
    id: 'accessibility-labels-missing', title: 'Accessibility labels/roles not detected', severity: 'medium',
    whyItMatters: 'Missing accessibility support hurts users with assistive technologies and app quality.',
    fix: 'Add accessibilityLabel, accessibilityRole, readable touch targets, and font scaling checks.',
    codexPrompt: 'Audit key controls for accessibility labels, roles, hints, touch target size, and screen reader behavior.'
  })] : [],

  ({ files }) => any(files, /width:\s*\d{3,}|height:\s*\d{3,}|fontSize:\s*[3-9]\d/i) ? [finding({
    id: 'fixed-size-ui-risk', title: 'Large fixed UI sizes detected', severity: 'medium',
    whyItMatters: 'Fixed sizes can break layouts on small phones and different screen densities.',
    fix: 'Use responsive spacing, flex layout, max/min sizes, and test small screens.',
    codexPrompt: 'Find large fixed widths/heights/font sizes. Make layout responsive for small Android phones without changing visual intent.'
  })] : [],

  ({ files }) => any(files, /NetInfo|offline|isConnected|queue|sync/i) ? [] : [finding({
    id: 'offline-readiness-missing', title: 'Offline/slow-network readiness not detected', severity: 'medium',
    whyItMatters: 'Mobile users often have poor connectivity; apps should fail gracefully.',
    fix: 'Add offline detection, retry, cached states, and clear user messages where needed.',
    codexPrompt: 'Add an offline/slow-network readiness plan using NetInfo, cached UI states, retries, and user-friendly error messages.'
  })],

  // Maintenance/operations
  ({ hasFile }) => !hasFile('.github/workflows/ci.yml') ? [finding({
    id: 'ci-missing', title: 'GitHub Actions CI missing', severity: 'medium',
    whyItMatters: 'Without CI, broken code can enter main branch unnoticed.',
    fix: 'Add CI to run install, TypeScript check, lint, tests, and build on every PR.',
    codexPrompt: 'Add GitHub Actions CI for npm install, TypeScript check, lint, tests, and build.'
  })] : [],

  ({ hasFile }) => !hasFile('README.md') ? [finding({
    id: 'readme-missing', title: 'README missing', severity: 'low',
    whyItMatters: 'A public repo without a strong README gets fewer users and contributors.',
    fix: 'Add install steps, screenshots, demo, roadmap, and contribution guide.',
    codexPrompt: 'Create a polished open-source README with demo, install, usage, roadmap, and contribution sections.'
  })] : [],

  ({ hasFile }) => !hasFile('CHANGELOG.md') ? [finding({
    id: 'changelog-missing', title: 'CHANGELOG missing', severity: 'low',
    whyItMatters: 'A changelog helps users understand updates and upgrade safely.',
    fix: 'Add CHANGELOG.md and update it for every release.',
    codexPrompt: 'Add a simple CHANGELOG.md following Keep a Changelog style.'
  })] : [],

  ({ files }) => any(files, /jest|vitest|testing-library|detox|maestro/i) ? [] : [finding({
    id: 'tests-missing', title: 'Test framework not detected', severity: 'medium',
    whyItMatters: 'Without tests, regressions are harder to catch before release.',
    fix: 'Add at least unit tests for utilities and smoke tests for critical flows.',
    codexPrompt: 'Add a practical test setup and smoke tests for login, onboarding, navigation, and critical app flows.'
  })],

  ({ files }) => any(files, /backup|restore|export data|data export|retention/i) ? [] : [finding({
    id: 'backup-retention-plan-missing', title: 'Backup/data retention plan not detected', severity: 'low',
    whyItMatters: 'Long-running apps need a plan for backups, retention, restore, and user deletion requests.',
    fix: 'Document backups, retention windows, restore process, and deletion handling.',
    codexPrompt: 'Create a production operations checklist for backups, data retention, restore testing, data export, and deletion requests.'
  })],

  ({ files }) => any(files, /rateLimit|throttle|debounce|captcha|abuse|spam/i) ? [] : [finding({
    id: 'abuse-protection-missing', title: 'Abuse/rate-limit strategy not detected', severity: 'medium',
    whyItMatters: 'Public apps can be abused through spam, scraping, repeated signups, or expensive API calls.',
    fix: 'Add backend rate limits, abuse monitoring, CAPTCHA where appropriate, and cost controls.',
    codexPrompt: 'Add an abuse-protection checklist for rate limiting, spam prevention, quota limits, expensive API protection, and monitoring.'
  })],

  ({ files }) => any(files, /rollback|release checklist|staged rollout|versionCode|versionName|eas submit|eas build/i) ? [] : [finding({
    id: 'release-rollback-plan-missing', title: 'Release/rollback plan not detected', severity: 'low',
    whyItMatters: 'Long-term apps need safe releases, staged rollout, and rollback plans.',
    fix: 'Document release checklist, versioning, staged rollout, monitoring, and rollback steps.',
    codexPrompt: 'Create a release checklist with versioning, production build, staged rollout, monitoring, rollback, and post-release verification.'
  })]
];
