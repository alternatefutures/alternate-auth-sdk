'use client';

/**
 * `<UserButton>`: the web app's account menu
 * (components/navigation/UserMenuDropdown.tsx): an avatar trigger, a
 * dropdown with the identity block, "Account settings", your own items and
 * a destructive "Log out". Radix DropdownMenu gives the keyboard and focus
 * behaviour (arrows, Home/End, Escape returns focus, typeahead).
 */

import { userInitials } from '@alternatefutures/ac-auth';
import { LogOut, Settings } from 'lucide-react';
import * as React from 'react';
import { useAuth, type AuthSignOutOptions } from '../context';
import { cn } from '../lib/utils';
import { Avatar, AvatarFallback, AvatarImage } from '../ui/avatar';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from '../ui/dropdown-menu';
import { useThemeAttribute } from './theme';

export const DEFAULT_ACCOUNT_URL = 'https://clouds.alternatefutures.ai/account/settings';

export interface UserButtonProps extends AuthSignOutOptions {
  /** Show the name next to the avatar (the web app shows the avatar alone). */
  showName?: boolean;
  /** Where "Account settings" goes. Default: the Alternate Clouds account settings. `null` hides it. */
  accountUrl?: string | null;
  /** Extra menu items, rendered between "Account settings" and "Log out". Use `<UserButtonItem>`. */
  children?: React.ReactNode;
  className?: string;
  signOutLabel?: React.ReactNode;
  accountLabel?: React.ReactNode;
}

export interface UserButtonItemProps {
  href?: string;
  onSelect?: () => void | Promise<void>;
  children: React.ReactNode;
  className?: string;
  variant?: 'default' | 'destructive';
}

/** A menu item for `<UserButton>`: a link when `href` is given, else a button. */
export function UserButtonItem({ href, onSelect, children, className, variant }: UserButtonItemProps) {
  if (href) {
    return (
      <DropdownMenuItem asChild className={className} variant={variant}>
        <a href={href}>{children}</a>
      </DropdownMenuItem>
    );
  }
  return (
    <DropdownMenuItem className={className} variant={variant} onSelect={() => void onSelect?.()}>
      {children}
    </DropdownMenuItem>
  );
}

export function UserButton({
  showName = false,
  accountUrl = DEFAULT_ACCOUNT_URL,
  children,
  className,
  signOutLabel = 'Log out',
  accountLabel = 'Account settings',
  returnTo,
}: UserButtonProps) {
  const { user, signOut, status } = useAuth();
  const themeAttr = useThemeAttribute();
  const [signingOut, setSigningOut] = React.useState(false);

  if (status !== 'signed-in' || !user) return null;

  const displayName = user.name || user.email || (user.wallet ? shortWalletLabel(user.wallet) : 'Account');
  const initials = userInitials(user);

  const handleSignOut = async () => {
    setSigningOut(true);
    try {
      await signOut({ returnTo });
    } finally {
      setSigningOut(false);
    }
  };

  return (
    <div className={cn('af-auth af-auth-user-button inline-flex', className)} data-slot="user-button" {...themeAttr}>
      <DropdownMenu>
        <DropdownMenuTrigger className="flex items-center gap-2 rounded-full outline-none" aria-label={showName ? undefined : `Account menu for ${displayName}`} data-slot="trigger">
          <Avatar className="size-8 cursor-pointer">
            {user.picture ? <AvatarImage src={user.picture} alt="" /> : null}
            <AvatarFallback>{initials.charAt(0)}</AvatarFallback>
          </Avatar>
          {showName ? <span className="text-sm font-medium">{displayName}</span> : null}
        </DropdownMenuTrigger>
        <DropdownMenuContent className={cn('af-auth min-w-72 rounded-lg bg-background p-2')} side="bottom" align="end" sideOffset={8} {...themeAttr}>
          <DropdownMenuLabel className="p-0 font-normal">
            <div className="flex items-center gap-3 px-2 py-2 text-left text-sm" data-slot="identity">
              <Avatar className="size-8 rounded-lg">
                {user.picture ? <AvatarImage src={user.picture} alt="" /> : null}
                <AvatarFallback className="rounded-lg">{initials.charAt(0)}</AvatarFallback>
              </Avatar>
              <div className="grid flex-1 text-left text-sm leading-tight">
                <span className="truncate font-medium">{displayName}</span>
                {user.email && user.email !== displayName ? <span className="truncate text-xs text-muted-foreground">{user.email}</span> : null}
                {user.org ? <span className="truncate text-xs text-muted-foreground">{user.org.name}</span> : null}
              </div>
            </div>
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          {accountUrl ? (
            <DropdownMenuItem asChild>
              <a href={accountUrl}>
                <Settings />
                {accountLabel}
              </a>
            </DropdownMenuItem>
          ) : null}
          {children}
          <DropdownMenuSeparator />
          <DropdownMenuItem variant="destructive" disabled={signingOut} onSelect={() => void handleSignOut()}>
            <LogOut />
            {signingOut ? 'Logging out...' : signOutLabel}
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );
}

function shortWalletLabel(did: string): string {
  const address = did.split(':').pop() ?? did;
  return address.length > 12 ? `${address.slice(0, 6)}...${address.slice(-4)}` : address;
}
