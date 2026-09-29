/**
 * @alternatefutures/ac-auth-react
 *
 * React components and hooks for Sign in with Alternate Clouds, built from
 * the same shadcn primitives, palette and typography as the Alternate Clouds
 * web app. Import the stylesheet once (`@alternatefutures/ac-auth-react/styles.css`)
 * unless the app already runs the web app's stylesheet (then pass
 * theme="inherit"), wrap the app in `<AuthProvider>`, and use the components.
 *
 * @packageDocumentation
 */

export { AuthProvider, clientAdapter, useAuth, useOrganization, useSession, useUser } from './context';
export type {
  AuthAdapter,
  AuthContextValue,
  AuthProviderProps,
  AuthSession,
  AuthSignInOptions,
  AuthSignOutOptions,
  AuthStatus,
  AuthTheme,
} from './context';

export { BRAND_BUTTON_CLASS, SIGN_IN_LABEL, SignInButton } from './components/SignInButton';
export type { SignInButtonProps } from './components/SignInButton';
export { AUTH_CARD_CLASS, SignIn } from './components/SignIn';
export type { SignInMethod, SignInProps } from './components/SignIn';
export { DEFAULT_ACCOUNT_URL, UserButton, UserButtonItem } from './components/UserButton';
export type { UserButtonItemProps, UserButtonProps } from './components/UserButton';
export { SignedIn, SignedOut } from './components/Signed';
export type { SignedProps } from './components/Signed';
export { Mark } from './components/Mark';
export type { MarkProps } from './components/Mark';

export type { AuthUser, OrganizationClaim, Session, TokenSet } from '@alternatefutures/ac-auth';
