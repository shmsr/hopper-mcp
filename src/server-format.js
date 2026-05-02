export const DEFAULT_MAX_TOOL_TEXT_CHARS = 120000;

// Wrap a tool's raw return value into the MCP CallToolResult shape (content +
// structuredContent). Large strings are truncated with provenance so clients
// can opt in to the full payload via include_full_result.
export function toolResult(result, { maxTextChars = DEFAULT_MAX_TOOL_TEXT_CHARS, includeFullResult = true } = {}) {
  const contentText = formatToolText(result, { maxTextChars });
  return {
    content: [{ type: "text", text: contentText }],
    structuredContent: structuredToolContent(result, { maxTextChars, includeFullResult }),
  };
}

export function formatToolText(result, { maxTextChars }) {
  const text = JSON.stringify(result, null, 2);
  if (!maxTextChars || maxTextChars < 0 || text.length <= maxTextChars) return text;
  return JSON.stringify(
    {
      truncated: true,
      originalChars: text.length,
      returnedChars: maxTextChars,
      preview: text.slice(0, maxTextChars),
    },
    null,
    2,
  );
}

export function structuredToolContent(result, { maxTextChars = DEFAULT_MAX_TOOL_TEXT_CHARS, includeFullResult = true } = {}) {
  if (typeof result === "string") {
    if (!maxTextChars || maxTextChars < 0 || result.length <= maxTextChars) return { result };
    return removeUndefined({
      result: includeFullResult ? result : undefined,
      resultPreview: result.slice(0, maxTextChars),
      truncated: true,
      originalChars: result.length,
      returnedChars: maxTextChars,
    });
  }
  const wrapped = result && typeof result === "object" && !Array.isArray(result) ? result : { result };
  if (!maxTextChars || maxTextChars < 0) return wrapped;
  // Mirror the truncation that formatToolText applies on the same payload.
  // Previously the object branch returned `wrapped` verbatim, which meant a
  // 50 MB tool result had its text content capped at 120 KB but its
  // structuredContent shipped the full 50 MB through stdio — defeating the
  // protection and risking host OOM / framing-layer limits.
  const serialized = JSON.stringify(wrapped);
  if (includeFullResult && serialized.length <= maxTextChars) return wrapped;
  return {
    truncated: true,
    originalChars: serialized.length,
    returnedChars: maxTextChars,
    preview: serialized.slice(0, maxTextChars),
  };
}

export function boundedNumber(value, fallback) {
  const parsed = Number(value ?? fallback);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(0, Math.floor(parsed));
}

function removeUndefined(object) {
  return Object.fromEntries(Object.entries(object).filter(([, value]) => value !== undefined));
}
