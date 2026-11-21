// Never publish a provider error verbatim: it can contain credentials or PR content.
// Only fixed categories and validated HTTP status codes may reach Action logs or traces.
export function sessionErrorCategory(message: string): string {
  // Also matches JSON error bodies such as `"status":400`.
  const status =
    message.match(
      /^(?:HTTP\s+|status"?(?:\s+code)?\s*[=:]\s*)?([45]\d{2})\b/i,
    )?.[1] ??
    message.match(
      /\b(?:HTTP\s+|status"?(?:\s+code)?\s*[=:]\s*)([45]\d{2})\b/i,
    )?.[1];
  if (status === "429") return "rate limited (HTTP 429)";
  if (status === "401" || status === "403")
    return `authentication or permission error (HTTP ${status})`;
  if (status?.startsWith("5")) return `provider server error (HTTP ${status})`;
  if (status) return `request rejected (HTTP ${status})`;
  if (
    /^(?:fetch failed|connection error|network error|ECONNRESET|ETIMEDOUT|ENOTFOUND)\b/i.test(
      message,
    )
  )
    return "network or transport error";
  return "unclassified provider or runtime error";
}
