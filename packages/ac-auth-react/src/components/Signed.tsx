'use client';

import * as React from 'react';
import { useAuth } from '../context';

export interface SignedProps {
  children?: React.ReactNode;
  /** Rendered while the session is still loading. Default nothing. */
  fallback?: React.ReactNode;
}

/** Renders its children only for a signed-in user. */
export function SignedIn({ children, fallback = null }: SignedProps) {
  const { status } = useAuth();
  if (status === 'loading') return <>{fallback}</>;
  return status === 'signed-in' ? <>{children}</> : null;
}

/** Renders its children only when nobody is signed in. */
export function SignedOut({ children, fallback = null }: SignedProps) {
  const { status } = useAuth();
  if (status === 'loading') return <>{fallback}</>;
  return status === 'signed-out' ? <>{children}</> : null;
}
