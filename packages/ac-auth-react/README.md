# @alternatefutures/ac-auth-react

React components and hooks for **Sign in with Alternate Clouds**: the
"Continue with Alternate Clouds" button, the sign-in card, the account menu,
`<SignedIn>` / `<SignedOut>` gates and hooks. Built from the same shadcn
primitives, palette and typeface as the Alternate Clouds web app, so the
sign-in looks like the platform the user is signing in with.

For a Next.js app use `@alternatefutures/ac-auth-next`, which re-exports these
components and keeps the tokens on the server. This package on its own is
for browser apps (Vite, single-page apps) where the browser holds the session.

## Install

```bash
npm install @alternatefutures/ac-auth-react @alternatefutures/ac-auth
```

## Use (browser app)

```tsx
import '@alternatefutures/ac-auth-react/styles.css';
import { createAuthClient } from '@alternatefutures/ac-auth';
import { AuthProvider, SignIn, SignedIn, SignedOut, UserButton, useUser } from '@alternatefutures/ac-auth-react';

const auth = createAuthClient({
  clientId: 'ac_...',
  redirectUri: `${window.location.origin}/callback`,
  scope: ['openid', 'profile', 'email', 'wallet'],
});

export function App() {
  return (
    <AuthProvider client={auth}>
      <SignedOut>
        <SignIn appName="My app" returnTo="/" />
      </SignedOut>
      <SignedIn>
        <UserButton />
        <Welcome />
      </SignedIn>
    </AuthProvider>
  );
}

function Welcome() {
  const { user } = useUser();
  return <p>Hello {user?.name ?? user?.email}</p>;
}
```

The provider finishes the sign-in by itself when it mounts on the redirect
URI, so `/callback` needs no code of its own.

## Components

| Component | What it is |
|---|---|
| `<AuthProvider client \| adapter initialSession theme>` | Holds the session. `theme`: `dark` (default, the web app's scheme), `light`, `system`, or `inherit` (your app already runs the web app's stylesheet). |
| `<SignInButton>` | The web app's brand call to action (`bg-orange-700`, size lg, full width) with the Alternate Clouds mark; `variant="outline"` for the secondary style. Busy state while redirecting. |
| `<SignIn>` | The web app's sign-in card: centered title, bold headline, the methods line, the button, terms and privacy links, errors in `text-destructive`. |
| `<UserButton>` | The web app's account menu: avatar trigger, identity block, "Account settings", your `<UserButtonItem>`s, destructive "Log out". Radix menu semantics. |
| `<SignedIn>` / `<SignedOut>` | Render children by status; `fallback` while loading. |
| `<Mark>` | The Alternate Clouds mark (`logo.svg`), `currentColor`. |

## Hooks

`useAuth()` (everything), `useUser()`, `useSession()`, `useOrganization()`.

## Styling

Two ways:

- **Your app runs the web app's stylesheet** (the starters do: `globals.css`
  copied from the web app, Tailwind v4). Add
  `@source "../node_modules/@alternatefutures/ac-auth-react/dist"` to your CSS
  entry and pass `theme="inherit"`. Nothing else to import.
- **Any other app**: import `@alternatefutures/ac-auth-react/styles.css` once.
  It carries the web app's palette scoped to the components (never your page)
  and follows `theme`.

Copies of the web app's `components/ui/{button,card,avatar,dropdown-menu}.tsx`
live in `src/ui`; keep them in sync with the web app.

## Accessibility

The sign-in card is a labelled `region` with a real heading and a
`role="alert"` error region. The account menu is a Radix menu: Enter, Space
and ArrowDown open; arrows, Home, End and typeahead move; Escape closes and
returns focus. The busy button is `aria-busy`.

## License

MIT
