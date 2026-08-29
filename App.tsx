import { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { PromptScanner } from './components/PromptScanner';
import { FileScanner } from './components/FileScanner';
import { LiveDashboard } from './components/LiveDashboard';
import { MultiAgentFlow } from './components/MultiAgentFlow';
import { PolicyEditor } from './components/PolicyEditor';
import { ApiKeyModal } from './components/ApiKeyModal';
import { checkGatewayHealth } from './services/api';
import type { ProtectResponse, PolicyConfig, GatewaySessionStats } from './types';
import { Cpu } from 'lucide-react';

export function App() {
  const [activeTab, setActiveTab] = useState<'scanner' | 'files' | 'dashboard' | 'agents'>('scanner');
  const [hasGeminiKey, setHasGeminiKey] = useState<boolean>(false);
  const [isApiKeyModalOpen, setIsApiKeyModalOpen] = useState<boolean>(false);
  const [isPolicyModalOpen, setIsPolicyModalOpen] = useState<boolean>(false);

  // Enterprise Security Policies State
  const [policy, setPolicy] = useState<PolicyConfig>({
    blockCriticalKeys: true,
    maskEmails: true,
    generalizeLocations: true,
    allowSyntheticReplacements: true,
    strictSanitization: false
  });

  // Gateway Live Session Stats (Core Feature 6)
  const [sessionStats, setSessionStats] = useState<GatewaySessionStats>({
    promptsScanned: 0,
    sensitiveItemsDetected: 0,
    credentialsBlocked: 0,
    promptsRewritten: 0,
    avgTaskPreservation: 98,
    riskBreakdown: {
      safe: 0,
      medium: 0,
      high: 0,
      critical: 0
    },
    recentScans: []
  });

  const checkHealth = async () => {
    try {
      const data = await checkGatewayHealth();
      setHasGeminiKey(data.hasGeminiKey);
    } catch {
      setHasGeminiKey(false);
    }
  };

  useEffect(() => {
    checkHealth();
  }, []);

  // Update session stats whenever a scan is completed
  const handleScanCompleted = (result: ProtectResponse) => {
    setSessionStats((prev) => {
      const newTotal = prev.promptsScanned + 1;
      const findingsCount = result.findings.length;
      const credsCount = result.findings.filter(
        (f) =>
          f.category.includes('Secret') ||
          f.type.includes('KEY') ||
          f.type.includes('PASSWORD') ||
          f.type.includes('DATABASE')
      ).length;

      const riskLvl = result.riskLevelBefore;
      const breakdown = { ...prev.riskBreakdown };
      if (riskLvl === 'CRITICAL') breakdown.critical += 1;
      else if (riskLvl === 'HIGH') breakdown.high += 1;
      else if (riskLvl === 'MEDIUM') breakdown.medium += 1;
      else breakdown.safe += 1;

      // Running average preservation
      const currentAvg = prev.promptsScanned === 0
        ? result.taskPreservationScore
        : Math.round((prev.avgTaskPreservation * prev.promptsScanned + result.taskPreservationScore) / newTotal);

      const snippet = result.originalPrompt.slice(0, 48) + (result.originalPrompt.length > 48 ? '...' : '');

      const newScanEvent = {
        id: `scan_${Date.now()}`,
        timestamp: new Date().toLocaleTimeString(),
        snippet,
        riskBefore: result.riskScoreBefore,
        riskAfter: result.riskScoreAfter,
        findingsCount,
        preservation: result.taskPreservationScore
      };

      return {
        promptsScanned: newTotal,
        sensitiveItemsDetected: prev.sensitiveItemsDetected + findingsCount,
        credentialsBlocked: prev.credentialsBlocked + credsCount,
        promptsRewritten: prev.promptsRewritten + 1,
        avgTaskPreservation: currentAvg,
        riskBreakdown: breakdown,
        recentScans: [newScanEvent, ...prev.recentScans].slice(0, 15)
      };
    });
  };

  const handleFileScanRecorded = (findingsCount: number, riskScore: number) => {
    setSessionStats((prev) => {
      const breakdown = { ...prev.riskBreakdown };
      if (riskScore >= 75) breakdown.critical += 1;
      else if (riskScore >= 50) breakdown.high += 1;
      else if (riskScore >= 20) breakdown.medium += 1;
      else breakdown.safe += 1;

      return {
        ...prev,
        sensitiveItemsDetected: prev.sensitiveItemsDetected + findingsCount,
        riskBreakdown: breakdown
      };
    });
  };

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 flex flex-col selection:bg-emerald-500/30 selection:text-emerald-300">
      {/* Top Navbar */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        hasGeminiKey={hasGeminiKey}
        onOpenApiKeyModal={() => setIsApiKeyModalOpen(true)}
        onOpenPolicyModal={() => setIsPolicyModalOpen(true)}
        sessionCount={sessionStats.promptsScanned}
      />

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* Tab 1: Prompt Scanner & Rewriter */}
        {activeTab === 'scanner' && (
          <PromptScanner
            onScanCompleted={handleScanCompleted}
            policy={policy}
          />
        )}

        {/* Tab 2: Secret & File Scanner */}
        {activeTab === 'files' && (
          <FileScanner
            onScanRecorded={handleFileScanRecorded}
          />
        )}

        {/* Tab 3: Live Session Dashboard */}
        {activeTab === 'dashboard' && (
          <LiveDashboard stats={sessionStats} />
        )}

        {/* Tab 4: Multi-Agent Deep Dive */}
        {activeTab === 'agents' && (
          <div className="space-y-6">
            <div className="glass-panel rounded-2xl p-6 border border-slate-800">
              <div className="flex items-center gap-3 mb-4 pb-3 border-b border-slate-800">
                <Cpu className="h-6 w-6 text-emerald-400" />
                <div>
                  <h2 className="text-lg font-bold text-white">PromptShield Multi-Agent Security Pipeline</h2>
                  <p className="text-xs text-slate-400">
                    Detailed walkthrough of the 5 cooperative autonomous guardrail stages
                  </p>
                </div>
              </div>

              <MultiAgentFlow />

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-6 text-xs font-mono">
                <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800">
                  <span className="text-cyan-400 font-bold block mb-1">STAGE 1 & 2: INTENT & PRIVACY AUDIT</span>
                  <p className="text-slate-300 font-sans leading-relaxed">
                    Evaluates prompt semantics and runs ultra-fast regex for known secret formats (OpenAI sk-*, Google AIza*, AWS AKIA*, connection strings) plus Gemini 2.5 Flash semantic classification for human names, addresses, and customer rosters.
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800">
                  <span className="text-amber-400 font-bold block mb-1">STAGE 3: CONTEXT-AWARE RISK REASONER</span>
                  <p className="text-slate-300 font-sans leading-relaxed">
                    Evaluates prompt context to generate a 0-100 severity score and plain-English "Explain WHY" reasoning, explaining why raw exposure to external LLMs creates data leakage risks.
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800">
                  <span className="text-purple-400 font-bold block mb-1">STAGE 4: REWRITE & TRANSFORMATION AGENT</span>
                  <p className="text-slate-300 font-sans leading-relaxed">
                    Executes configurable transformation modes (Redaction tokens, Character masking, Geographic generalization, or Synthetic persona replacement) with Temperature 0.1 for high grammatical fidelity.
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800">
                  <span className="text-emerald-400 font-bold block mb-1">STAGE 5: INTENT PRESERVATION VERIFIER</span>
                  <p className="text-slate-300 font-sans leading-relaxed">
                    Verifies that the sanitized prompt still answers the original developer question and measures the Task Intent Preservation Score (target &gt; 95%).
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950/80 py-4 px-4 sm:px-6 lg:px-8 text-center text-xs text-slate-500 font-mono">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-emerald-400"></span>
            <span>PromptShield AI — Security Gateway v1.0.0</span>
          </div>
          <div>
            Built with React 19 • Tailwind CSS • Gemini 2.5 Flash (Structured JSON Mode)
          </div>
        </div>
      </footer>

      {/* Modals */}
      <PolicyEditor
        isOpen={isPolicyModalOpen}
        onClose={() => setIsPolicyModalOpen(false)}
        policy={policy}
        setPolicy={setPolicy}
      />

      <ApiKeyModal
        isOpen={isApiKeyModalOpen}
        onClose={() => setIsApiKeyModalOpen(false)}
        hasGeminiKey={hasGeminiKey}
        onKeyUpdated={checkHealth}
      />
    </div>
  );
}

export default App;
