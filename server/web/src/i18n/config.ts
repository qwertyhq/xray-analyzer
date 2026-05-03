export const locales = ['ru', 'en'] as const;
export type Locale = typeof locales[number];
export const defaultLocale: Locale = 'ru';
