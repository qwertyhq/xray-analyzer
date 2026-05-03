/**
 * Check if date string is valid (not zero time or year before 2000)
 */
export function isValidDate(dateStr: string | undefined | null): boolean {
  if (!dateStr) return false;
  const date = new Date(dateStr);
  return !isNaN(date.getTime()) && date.getFullYear() > 2000;
}

/**
 * Format date as relative time (e.g., "2 minutes ago", "1 hour ago")
 */
export function formatRelativeTime(dateStr: string | undefined | null): string {
  if (!dateStr || !isValidDate(dateStr)) return 'Never';
  
  const date = new Date(dateStr);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffSec = Math.floor(diffMs / 1000);
  const diffMin = Math.floor(diffSec / 60);
  const diffHour = Math.floor(diffMin / 60);
  const diffDay = Math.floor(diffHour / 24);
  
  if (diffSec < 60) return 'Just now';
  if (diffMin < 60) return `${diffMin} minute${diffMin > 1 ? 's' : ''} ago`;
  if (diffHour < 24) return `${diffHour} hour${diffHour > 1 ? 's' : ''} ago`;
  if (diffDay < 7) return `${diffDay} day${diffDay > 1 ? 's' : ''} ago`;
  
  return date.toLocaleDateString();
}

/**
 * Format a number with locale-specific separators
 */
export function formatNumber(num: number): string {
  return num.toLocaleString();
}

/**
 * Calculate percentage
 */
export function percentage(value: number, total: number): number {
  if (total === 0) return 0;
  return (value / total) * 100;
}

/**
 * Truncate string with ellipsis
 */
export function truncate(str: string, maxLength: number): string {
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength - 3) + "...";
}
