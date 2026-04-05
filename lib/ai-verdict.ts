import { generateText, Output } from "ai";
import { z } from "zod";
import type { LogEvent, TriggeredAlert } from "./rule-engine";

const VerdictSchema = z.object({
  isThreat: z
    .boolean()
    .describe("Whether this is a genuine security threat"),
  confidence: z
    .number()
    .min(0)
    .max(1)
    .describe("Confidence score between 0 and 1"),
  severity: z
    .enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"])
    .describe("Threat severity if isThreat is true, otherwise NONE"),
  reasoning: z
    .string()
    .describe("2-3 sentence explanation of why this verdict was reached"),
  recommendedAction: z
    .enum([
      "disable_access_keys",
      "detach_admin_policy",
      "enable_cloudtrail",
      "block_s3_public_access",
      "quarantine_user",
      "notify_admin",
      "no_action",
    ])
    .describe("Best AWS remediation action for this threat"),
});

export type AIVerdict = z.infer<typeof VerdictSchema>;

export interface EnrichedAlert extends TriggeredAlert {
  anomaly_score:  number;
  ai_verdict:     string;
  ai_confidence:  number;
  ai_reasoning:   string;
  ai_action:      string;
  action_taken:   string;
  action_status:  string;
  is_anomaly:     boolean;
}

export async function getAIVerdict(
  event:        LogEvent,
  ruleAlerts:   TriggeredAlert[],
  anomalyScore: number,
): Promise<AIVerdict> {
  const { experimental_output } = await generateText({
    model: "openai/gpt-4.1",
    output: Output.object({ schema: VerdictSchema }),
    system: `You are an expert AWS cloud security analyst for an automated Intrusion Detection System.
Your verdicts trigger real AWS remediation actions — be accurate and conservative.
Only flag as CRITICAL or HIGH when evidence is strong and unambiguous.
Consider both rule-engine matches AND the ML anomaly score together for your final decision.
For clearly legitimate patterns (automated CI/CD, known admin operations), return isThreat=false.`,
    prompt: `Analyse this AWS CloudTrail security event and provide a final verdict.

EVENT DETAILS:
${JSON.stringify(event, null, 2)}

ML ANOMALY SCORE: ${anomalyScore.toFixed(3)}
(0.0 = perfectly normal behaviour · 1.0 = highly anomalous)

RULE ENGINE MATCHES:
${
  ruleAlerts.length > 0
    ? ruleAlerts
        .map(a => `• [${a.rule_id}] ${a.rule_name} (${a.severity})\n  ${a.details}`)
        .join("\n")
    : "• None — flagged by ML anomaly detection only"
}

Using all available signals, determine if this is a genuine threat and what remediation action AWS should take.`,
  });

  return experimental_output as AIVerdict;
}
