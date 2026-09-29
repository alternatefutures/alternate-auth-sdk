import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import * as React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { BRAND_BUTTON_CLASS, SIGN_IN_LABEL, SignIn, SignInButton, SignedIn, SignedOut, UserButton, UserButtonItem, useAuth, useOrganization, useUser } from '../src';
import { AuthProvider } from '../src/context';
import { Wrapper, fakeAdapter, session } from './helpers';

describe('<AuthProvider> and hooks', () => {
  it('starts from the adapter snapshot, then loads, and tracks changes', async () => {
    const adapter = fakeAdapter(session());
    function Probe() {
      const { status, isSignedIn } = useAuth();
      const { user } = useUser();
      const { organization, role } = useOrganization();
      return <p>{status}|{String(isSignedIn)}|{user?.email}|{organization?.name}|{role}</p>;
    }
    render(<Wrapper adapter={adapter}><Probe /></Wrapper>);
    expect(screen.getByText('signed-in|true|dev@example.com|Acme|OWNER')).toBeTruthy();
    act(() => adapter.set(null));
    expect(screen.getByText('signed-out|false|||')).toBeTruthy();
  });

  it('shows loading until the adapter answers when there is no snapshot', async () => {
    const adapter = fakeAdapter(null);
    adapter.peek = undefined;
    let resolve!: (s: null) => void;
    adapter.getSession.mockImplementation(() => new Promise<null>((r) => { resolve = r; }));
    function Probe() {
      return <p>{useAuth().status}</p>;
    }
    render(<Wrapper adapter={adapter}><Probe /></Wrapper>);
    expect(screen.getByText('loading')).toBeTruthy();
    await waitFor(() => expect(adapter.getSession).toHaveBeenCalled());
    await act(async () => resolve(null));
    expect(screen.getByText('signed-out')).toBeTruthy();
  });

  it('finishes a callback on mount and reports where to continue', async () => {
    const adapter = fakeAdapter(null);
    adapter.completeCallback.mockResolvedValue({ session: session(), returnTo: '/dashboard' });
    const onSignedIn = vi.fn();
    function Probe() {
      return <p>{useAuth().status}</p>;
    }
    render(<AuthProvider adapter={adapter} onSignedIn={onSignedIn}><Probe /></AuthProvider>);
    await waitFor(() => expect(screen.getByText('signed-in')).toBeTruthy());
    expect(onSignedIn).toHaveBeenCalledWith('/dashboard', expect.objectContaining({ status: 'active' }));
    expect(adapter.getSession).not.toHaveBeenCalled();
  });

  it('surfaces a failed callback as an error and signed-out', async () => {
    const adapter = fakeAdapter(null);
    adapter.completeCallback.mockRejectedValue(new Error('boom'));
    const onError = vi.fn();
    function Probe() {
      const { status, error } = useAuth();
      return <p>{status}|{error?.message}</p>;
    }
    render(<AuthProvider adapter={adapter} onError={onError}><Probe /></AuthProvider>);
    await waitFor(() => expect(screen.getByText('signed-out|boom')).toBeTruthy());
    expect(onError).toHaveBeenCalled();
  });

  it('throws outside a provider and without a source', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    function Probe() {
      useAuth();
      return null;
    }
    expect(() => render(<Probe />)).toThrow(/inside <AuthProvider>/);
    expect(() => render(<AuthProvider />)).toThrow(/client.*adapter/);
    spy.mockRestore();
  });
});

describe('<SignedIn> / <SignedOut>', () => {
  it('render by status, with a fallback while loading', async () => {
    const adapter = fakeAdapter(null);
    adapter.peek = undefined;
    let resolve!: (s: ReturnType<typeof session>) => void;
    adapter.getSession.mockImplementation(() => new Promise((r) => { resolve = r; }));
    render(
      <Wrapper adapter={adapter}>
        <SignedIn fallback={<span>loading-in</span>}>in</SignedIn>
        <SignedOut fallback={<span>loading-out</span>}>out</SignedOut>
      </Wrapper>,
    );
    expect(screen.getByText('loading-in')).toBeTruthy();
    expect(screen.getByText('loading-out')).toBeTruthy();
    await waitFor(() => expect(adapter.getSession).toHaveBeenCalled());
    await act(async () => resolve(session()));
    expect(screen.getByText('in')).toBeTruthy();
    expect(screen.queryByText('out')).toBeNull();
    act(() => adapter.set(null));
    expect(screen.getByText('out')).toBeTruthy();
    expect(screen.queryByText('in')).toBeNull();
  });
});

describe('<SignInButton>', () => {
  it('is the web app brand button, labelled "Continue with Alternate Clouds", starts the sign-in and shows a busy state', async () => {
    const adapter = fakeAdapter(null);
    let release!: () => void;
    adapter.signIn.mockImplementation(() => new Promise<void>((r) => { release = r; }));
    render(<Wrapper adapter={adapter}><SignInButton returnTo="/after" scope="openid wallet" /></Wrapper>);
    const button = screen.getByRole('button', { name: SIGN_IN_LABEL });
    expect(button.getAttribute('data-af-theme')).toBe('dark');
    for (const cls of BRAND_BUTTON_CLASS.split(' ')) expect(button.className).toContain(cls);
    expect(button.className).toContain('w-full');
    expect(button.querySelector('[data-slot=mark]')).toBeTruthy();
    fireEvent.click(button);
    expect(adapter.signIn).toHaveBeenCalledWith({ returnTo: '/after', scope: 'openid wallet', prompt: undefined, loginHint: undefined });
    await waitFor(() => expect(button.getAttribute('aria-busy')).toBe('true'));
    expect((button as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText('Redirecting...')).toBeTruthy();
    fireEvent.click(button);
    expect(adapter.signIn).toHaveBeenCalledTimes(1);
    await act(async () => release());
  });

  it('recovers from a failed sign-in, honours a custom label, the outline variant and the theme', async () => {
    const adapter = fakeAdapter(null);
    adapter.signIn.mockRejectedValue(new Error('nope'));
    render(<Wrapper adapter={adapter} theme="light"><SignInButton variant="outline">Log in</SignInButton></Wrapper>);
    const button = screen.getByRole('button', { name: 'Log in' });
    expect(button.getAttribute('data-af-theme')).toBe('light');
    expect(button.className).not.toContain('bg-orange-700');
    expect(button.className).toContain('border');
    fireEvent.click(button);
    await waitFor(() => expect((button as HTMLButtonElement).disabled).toBe(false));
  });

  it('sets no theme attribute when inheriting', () => {
    const adapter = fakeAdapter(null);
    render(<Wrapper adapter={adapter} theme="inherit"><SignInButton /></Wrapper>);
    expect(screen.getByRole('button').hasAttribute('data-af-theme')).toBe(false);
  });
});

describe('<SignIn>', () => {
  it('is the web app auth card: a labelled region, the title, the two-line description, the button and the legal links', () => {
    const adapter = fakeAdapter(null);
    render(<Wrapper adapter={adapter}><SignIn appName="Acme Notes" termsUrl="/terms" privacyUrl="/privacy" /></Wrapper>);
    const region = screen.getByRole('region', { name: 'Sign in to Acme Notes' });
    expect(region.className).toContain('py-10');
    expect(region.className).toContain('dark:border-[#444444]');
    const heading = screen.getByRole('heading', { level: 1, name: 'Sign in to Acme Notes' });
    expect(heading.className).toContain('text-3xl');
    expect(screen.getByText('Use your Alternate Clouds account')).toBeTruthy();
    expect(screen.getByText('Email code')).toBeTruthy();
    expect(screen.getByText('SMS code')).toBeTruthy();
    expect(screen.getByText('Ethereum wallet')).toBeTruthy();
    expect(screen.getByRole('button', { name: SIGN_IN_LABEL })).toBeTruthy();
    expect(screen.getByRole('link', { name: 'the terms' }).getAttribute('href')).toBe('/terms');
    expect(screen.getByRole('link', { name: 'the privacy policy' }).getAttribute('href')).toBe('/privacy');
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('announces a provider error in an alert region and supports a custom heading level and method list', async () => {
    const adapter = fakeAdapter(null);
    adapter.completeCallback.mockRejectedValue(Object.assign(new Error('denied'), { error: 'access_denied' }));
    render(<Wrapper adapter={adapter}><SignIn headingLevel={2} methods={['email']} /></Wrapper>);
    await waitFor(() => expect(screen.getByRole('alert').textContent).toMatch(/cancelled/));
    expect(screen.getByRole('alert').className).toContain('text-destructive');
    expect(screen.getByRole('heading', { level: 2, name: 'Sign in' })).toBeTruthy();
    expect(screen.getByText('Email code')).toBeTruthy();
    expect(screen.queryByText('SMS code')).toBeNull();
  });
});

describe('<UserButton>', () => {
  function open(trigger: HTMLElement) {
    // Radix opens on a mouse pointerdown or on Enter/Space/ArrowDown; the keyboard path is deterministic in jsdom.
    fireEvent.keyDown(trigger, { key: 'ArrowDown' });
  }

  it('renders nothing when signed out and the web app avatar trigger when signed in', () => {
    const adapter = fakeAdapter(null);
    const { rerender } = render(<Wrapper adapter={adapter}><UserButton /></Wrapper>);
    expect(screen.queryByRole('button')).toBeNull();
    act(() => adapter.set(session()));
    rerender(<Wrapper adapter={adapter}><UserButton /></Wrapper>);
    const trigger = screen.getByRole('button', { name: 'Account menu for Dev One' });
    expect(trigger.getAttribute('aria-haspopup')).toBe('menu');
    expect(trigger.getAttribute('aria-expanded')).toBe('false');
    expect(trigger.className).toContain('rounded-full');
    expect(trigger.textContent).toContain('D');
  });

  it('opens the account menu: identity, Account settings, custom items, Log out; arrows and Escape work', async () => {
    const adapter = fakeAdapter(session());
    const onSelect = vi.fn();
    render(
      <Wrapper adapter={adapter}>
        <UserButton showName>
          <UserButtonItem onSelect={onSelect}>Settings</UserButtonItem>
        </UserButton>
      </Wrapper>,
    );
    const trigger = screen.getByRole('button', { name: /Dev One/ });
    open(trigger);
    const menu = await screen.findByRole('menu');
    expect(trigger.getAttribute('aria-expanded')).toBe('true');
    expect(menu.className).toContain('min-w-72');
    const items = screen.getAllByRole('menuitem');
    expect(items.map((i) => i.textContent)).toEqual(['Account settings', 'Settings', 'Log out']);
    expect((items[0] as HTMLAnchorElement).getAttribute('href')).toContain('clouds.alternatefutures.ai/account/settings');
    expect(items[2]!.getAttribute('data-variant')).toBe('destructive');
    expect(menu.textContent).toContain('dev@example.com');
    expect(menu.textContent).toContain('Acme');

    await waitFor(() => expect(menu.contains(document.activeElement)).toBe(true));
    fireEvent.keyDown(document.activeElement!, { key: 'ArrowDown' });
    await waitFor(() => expect(document.activeElement).toBe(items[0]));
    fireEvent.keyDown(document.activeElement!, { key: 'ArrowDown' });
    await waitFor(() => expect(document.activeElement).toBe(items[1]));
    fireEvent.keyDown(document.activeElement!, { key: 'End' });
    await waitFor(() => expect(document.activeElement).toBe(items[2]));

    fireEvent.keyDown(document.activeElement!, { key: 'Escape' });
    await waitFor(() => expect(screen.queryByRole('menu')).toBeNull());
    expect(document.activeElement).toBe(trigger);

    open(trigger);
    const custom = await screen.findByRole('menuitem', { name: 'Settings' });
    fireEvent.click(custom);
    await waitFor(() => expect(onSelect).toHaveBeenCalled());
    await waitFor(() => expect(screen.queryByRole('menu')).toBeNull());
  });

  it('logs out from the menu and hides afterwards', async () => {
    const adapter = fakeAdapter(session());
    render(<Wrapper adapter={adapter}><UserButton returnTo="/bye" /></Wrapper>);
    open(screen.getByRole('button'));
    fireEvent.click(await screen.findByRole('menuitem', { name: 'Log out' }));
    await waitFor(() => expect(adapter.signOut).toHaveBeenCalledWith({ returnTo: '/bye' }));
    await waitFor(() => expect(screen.queryByRole('button')).toBeNull());
  });
});
