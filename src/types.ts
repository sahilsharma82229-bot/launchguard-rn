export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  file?: string;
  evidence?: string;
  whyItMatters: string;
  fix: string;
  codexPrompt: string;
}

export interface ScanResult {
  projectPath: string;
  score: number;
  findings: Finding[];
  summary: Record<Severity, number>;
  generatedAt: string;
}
