'use client';

/**
 * "Continue with Alternate Clouds": the web app's primary sign-in call to
 * action (`brandButtonClass` on AuthPage: orange, white text, size lg, full
 * width) with the Alternate Clouds mark. `variant="outline"` gives the
 * secondary style the app uses for "Continue with wallet".
 */

import { Loader2 } from 'lucide-react';
import * as React from 'react';
import { useAuth, type AuthSignInOptions } from '../context';
import { cn } from '../lib/utils';
import { Button } from '../ui/button';
import { Mark } from './Mark';
import { useThemeAttribute } from './theme';

type ButtonProps = React.ComponentProps<typeof Button>;

export const SIGN_IN_LABEL = 'Continue with Alternate Clouds';

/** The web app's brand button classes (components/auth/AuthPage.tsx `brandButtonClass`). */
export const BRAND_BUTTON_CLASS = 'bg-orange-700 text-white hover:bg-orange-700/90';

export interface SignInButtonProps extends Omit<ButtonProps, 'onClick' | 'children' | 'variant'>, AuthSignInOptions {
  /** `brand` (default): the app's orange call to action. `outline`: the secondary style. */
  variant?: 'brand' | 'outline';
  /** Label override. Default "Continue with Alternate Clouds". */
  children?: React.ReactNode;
  /** Shown while redirecting. Default "Redirecting...". */
  busyLabel?: React.ReactNode;
  onClick?: (event: React.MouseEvent<HTMLButtonElement>) => void;
  hideMark?: boolean;
}

export function SignInButton({
  children,
  busyLabel = 'Redirecting...',
  onClick,
  hideMark = false,
  returnTo,
  scope,
  prompt,
  loginHint,
  className,
  variant = 'brand',
  size = 'lg',
  disabled,
  ...rest
}: SignInButtonProps) {
  const { signIn } = useAuth();
  const [busy, setBusy] = React.useState(false);
  const themeAttr = useThemeAttribute();

  const handleClick = async (event: React.MouseEvent<HTMLButtonElement>) => {
    onClick?.(event);
    if (event.defaultPrevented || busy) return;
    setBusy(true);
    try {
      await signIn({ returnTo, scope, prompt, loginHint });
    } catch {
      setBusy(false);
    }
  };

  return (
    <Button
      type="button"
      variant={variant === 'outline' ? 'outline' : 'default'}
      size={size}
      className={cn('af-auth af-auth-signin-button w-full', variant === 'brand' && BRAND_BUTTON_CLASS, className)}
      data-slot="sign-in-button"
      aria-busy={busy || undefined}
      disabled={disabled || busy}
      onClick={handleClick}
      {...themeAttr}
      {...rest}
    >
      {busy ? <Loader2 className="animate-spin" /> : !hideMark ? <Mark /> : null}
      {busy ? busyLabel : children ?? SIGN_IN_LABEL}
    </Button>
  );
}
