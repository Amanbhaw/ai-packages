export interface Receipt {
  spec: string;
  step: number;
  model: string;
  prompt_commit: string;
  response_commit: string;
  tool_commit: string;
  cost: number;
  timestamp: number;
  prev_hash: string;
  hash: string;
  sig?: string;
}

export interface FoldedReceipt {
  spec: string;
  count: number;
  root: string;
  first_step: number | null;
  last_step: number | null;
}

export interface CreateReceiptOptions {
  step: number;
  model: string;
  prompt: unknown;
  response: unknown;
  toolCalls?: unknown;
  cost?: number;
  timestamp?: number;
  prevHash?: string;
  salt?: string;
  secretKey?: string | null;
}

export const VERSION: string;
export const SPEC: string;

export function createReceipt(opts: CreateReceiptOptions): Receipt;
export function verifyReceipt(r: Receipt, secretKey?: string): boolean;
export function verifyChain(receipts: Receipt[], secretKey?: string): boolean;
export function foldReceipts(receipts: Receipt[]): FoldedReceipt;
export function verifyFold(folded: FoldedReceipt, receipts: Receipt[]): boolean;
export function openCommitment(commitHex: string, value: unknown, salt: string): boolean;
export function exportComplianceReport(folded: FoldedReceipt, receipts: Receipt[], fmt?: 'markdown' | 'json', proKey?: string | null): string;
export function newSalt(): string;
