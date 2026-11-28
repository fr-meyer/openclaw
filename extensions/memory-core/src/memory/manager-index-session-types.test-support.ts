export type MemoryIndexSessionSeedParams = {
  messages: Array<{
    content: string;
    role: "assistant" | "user";
    senderIsOwner?: boolean;
    timestamp: number | string;
  }>;
  sessionId: string;
  sessionKey?: string;
};
