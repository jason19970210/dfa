import { z } from "zod";

/** Shared by the MCP tool and the CLI so neither path bypasses validation. */
export const CaseSchema = z.object({
  id: z.string().min(1).describe("Case identifier."),
  examiner: z.string().min(1).describe("Human examiner of record (the agent acted as their tool)."),
  subject: z.string().optional().describe("Subject of investigation."),
  notes: z.string().optional().describe("Case notes."),
});

export const FindingSchema = z.object({
  id: z.string().min(1).describe("Finding ID, e.g. F-01."),
  observation: z.string().describe("What was observed."),
  evidence: z.array(z.number().int().positive()).optional().describe("Custody seq numbers supporting this finding."),
  limitation: z.string().optional().describe("What this finding cannot establish."),
  confidence: z.enum(["high", "medium", "low"]).optional(),
});

export const FindingsSchema = z.array(FindingSchema);
