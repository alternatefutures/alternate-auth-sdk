import { useAuth } from '../context';

/**
 * The `data-af-theme` attribute the stylesheet keys on. `inherit` sets no
 * attribute, so the host's own token values apply.
 */
export function useThemeAttribute(): { 'data-af-theme'?: 'light' | 'dark' | 'system' } {
  const { theme } = useAuth();
  return theme === 'inherit' ? {} : { 'data-af-theme': theme };
}
