'use client';

/**
 * `<SignIn>`: the web app's sign-in card (components/auth/AuthPage.tsx:
 * `authCardClass`, the centered title, the two-line description, errors in
 * `text-destructive`, the full-width brand button) with one button instead
 * of the method list, because every method lives on the Alternate Clouds
 * page the issuer sends the user to.
 */

import { Mail, Smartphone, Wallet } from 'lucide-react';
import * as React from 'react';
import { useAuth, type AuthSignInOptions } from '../context';
import { cn } from '../lib/utils';
import { Card, CardContent, CardDescription, CardHeader } from '../ui/card';
import { SignInButton } from './SignInButton';
import { useThemeAttribute } from './theme';

export type SignInMethod = 'email' | 'sms' | 'wallet';

const METHOD_LABELS: Record<SignInMethod, string> = {
  email: 'Email code',
  sms: 'SMS code',
  wallet: 'Ethereum wallet',
};

const METHOD_ICONS: Record<SignInMethod, React.ComponentType<{ className?: string }>> = {
  email: Mail,
  sms: Smartphone,
  wallet: Wallet,
};

/** The web app's auth card classes (AuthPage `authCardClass`, without the marketing-panel sizing). */
export const AUTH_CARD_CLASS = 'w-full px-6 py-10 dark:border-[#444444]';

export interface SignInProps extends AuthSignInOptions {
  /** Your app's name, used in the title. */
  appName?: string;
  /** Your logo, rendered above the title. */
  logo?: React.ReactNode;
  title?: React.ReactNode;
  /** The bold line under the title. Default "Use your Alternate Clouds account". */
  headline?: React.ReactNode;
  /** The muted line under the headline. Default names the methods. */
  description?: React.ReactNode;
  /** Methods listed in the description. Default: all three. */
  methods?: SignInMethod[];
  termsUrl?: string;
  privacyUrl?: string;
  /** Heading level of the title. Default 1. */
  headingLevel?: 1 | 2 | 3;
  /** Extra content under the button. */
  children?: React.ReactNode;
  className?: string;
  errorMessage?: React.ReactNode;
}

export function SignIn({
  appName,
  logo,
  title,
  headline = 'Use your Alternate Clouds account',
  description,
  methods = ['email', 'sms', 'wallet'],
  termsUrl,
  privacyUrl,
  headingLevel = 1,
  children,
  className,
  errorMessage,
  returnTo,
  scope,
  prompt,
  loginHint,
}: SignInProps) {
  const { error } = useAuth();
  const themeAttr = useThemeAttribute();
  const titleId = React.useId();
  const descriptionId = React.useId();
  const Heading = `h${headingLevel}` as 'h1' | 'h2' | 'h3';
  const heading = title ?? (appName ? `Sign in to ${appName}` : 'Sign in');
  const message = errorMessage ?? (error ? describeError(error) : null);

  return (
    <Card
      className={cn('af-auth af-auth-signin max-w-md', AUTH_CARD_CLASS, className)}
      data-slot="sign-in"
      role="region"
      aria-labelledby={titleId}
      aria-describedby={descriptionId}
      {...themeAttr}
    >
      <CardHeader className="gap-6 pb-4">
        {logo ? <div className="flex justify-center" data-slot="logo">{logo}</div> : null}
        <Heading id={titleId} data-slot="card-title" className={cn('leading-none font-semibold', 'text-center text-3xl font-normal')}>
          {heading}
        </Heading>
        <CardDescription id={descriptionId} className="flex flex-col items-center gap-1 text-center">
          <span className="text-sm font-semibold text-foreground">{headline}</span>
          {description !== undefined ? (
            <span>{description}</span>
          ) : methods.length > 0 ? (
            <span className="inline-flex flex-wrap items-center justify-center gap-x-3 gap-y-1" data-slot="methods">
              {methods.map((method) => {
                const Icon = METHOD_ICONS[method];
                return (
                  <span key={method} className="inline-flex items-center gap-1">
                    <Icon className="size-3.5" aria-hidden="true" />
                    {METHOD_LABELS[method]}
                  </span>
                );
              })}
            </span>
          ) : null}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-2">
        {message ? (
          <div role="alert" className="text-destructive text-sm" data-slot="error">
            {message}
          </div>
        ) : null}
        <SignInButton returnTo={returnTo} scope={scope} prompt={prompt} loginHint={loginHint} />
        {children}
        {termsUrl || privacyUrl ? (
          <p className="pt-2 text-center text-xs text-muted-foreground" data-slot="legal">
            By continuing you agree to {termsUrl ? <a className="underline underline-offset-4 hover:text-foreground" href={termsUrl}>the terms</a> : 'the terms'}
            {privacyUrl ? <> and <a className="underline underline-offset-4 hover:text-foreground" href={privacyUrl}>the privacy policy</a></> : null}.
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}

function describeError(error: Error): string {
  const code = (error as { code?: string }).code;
  const oauth = (error as { error?: string }).error;
  if (oauth === 'access_denied') return 'The sign-in was cancelled. You can try again.';
  if (code === 'network_error' || code === 'discovery_failed') return 'The sign-in service could not be reached. Check your connection and try again.';
  if (code === 'no_transaction' || code === 'invalid_state') return 'This sign-in link is not valid any more. Start again.';
  return 'The sign-in could not be completed. Try again.';
}
