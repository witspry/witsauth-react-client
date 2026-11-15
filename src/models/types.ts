export interface OAuth2Storage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
  clear?(): void;
}

export class OAuthCallbackError extends Error {
  public readonly code: string;
  public readonly description: string | undefined;

  constructor(code: string, description?: string) {
    super(description ? `OAuth Error (${code}): ${description}` : `OAuth Error: ${code}`);
    this.name = 'OAuthCallbackError';
    this.code = code;
    this.description = description;
  }
}

export interface ImpersonationActor {
  readonly sub: string;
  readonly ticket_ref?: string | undefined;
  readonly sessionId?: string | undefined;
  readonly [key: string]: unknown;
}

export interface OAuth2Config {
  mode?: 'spa' | undefined;
  clientId: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  redirectUri: string;
  revokeEndpoint?: string | undefined;
  userInfoEndpoint?: string | undefined;
  scope?: string | undefined;
  audience?: string | undefined;
  responseType?: string | undefined;
  codeChallengeMethod?: 'S256' | undefined;
  storage?: 'localStorage' | 'sessionStorage' | 'custom' | undefined;
  customStorage?: OAuth2Storage | undefined;
  autoRefresh?: boolean | undefined;
  refreshThreshold?: number | undefined;
  logLevel?: 'none' | 'error' | 'warn' | 'info' | 'debug' | undefined;
  nonce?: string | undefined;
  redirectRoute?: string | undefined;
  logoutRedirectRoute?: string | undefined;
  logoutEndpoint?: string | undefined;
  oAuthProvider?: 'witsauth' | string | undefined;
  theme?: 'light' | 'dark' | 'system' | (() => 'light' | 'dark' | 'system' | string) | undefined;
  onCallbackError?: ((error: OAuthCallbackError) => void) | undefined;
}

export interface TokenInfo {
  accessToken: string;
  refreshToken?: string | undefined;
  tokenType: string;
  expiresAt: number;
  scope?: string | undefined;
  idToken?: string | undefined;
}

export interface AuthState {
  isAuthenticated: boolean;
  isLoading: boolean;
  tokenInfo?: TokenInfo | undefined;
  error?: string | undefined;
}

export interface UserInfo {
  sub?: string | undefined;
  name?: string | undefined;
  given_name?: string | undefined;
  family_name?: string | undefined;
  email?: string | undefined;
  email_verified?: boolean | undefined;
  phone_number?: string | undefined;
  phone_number_verified?: boolean | undefined;
  roles?: string[] | undefined;
  permissions?: string[] | undefined;
  amr?: string[] | undefined;
  act?: ImpersonationActor | undefined;
  [key: string]: unknown;
}

export type UserProfile = UserInfo;

export interface AuthorizeOptions {
  prompt?: 'login' | 'consent' | 'select_account' | 'none' | undefined;
  scope?: string | undefined;
  audience?: string | undefined;
  returnTo?: string | undefined;
  loginHint?: string | undefined;
  extraParams?: Readonly<Record<string, string>> | undefined;
}

export interface BffImpersonationSessionInfo {
  readonly active: boolean;
  readonly impersonatedByUserId: string;
  readonly ticketRef: string;
  readonly expiresAtEpochSec: number;
}

export interface BffSessionPayload<TUser = UserInfo, TProfile = unknown> {
  readonly isAuthenticated: boolean;
  readonly user: TUser | null;
  readonly profile?: TProfile | null | undefined;
  readonly impersonation?: BffImpersonationSessionInfo | null | undefined;
}

export interface LogoutResult {
  readonly loggedOut: boolean;
  readonly upstreamRevoked: boolean;
  readonly locallyRevoked: boolean;
}

export interface ClearStaleSessionResult {
  readonly cleared: boolean;
  readonly activeSession: boolean;
  readonly status?: number | undefined;
  readonly transientOutage?: boolean | undefined;
  readonly errorCode?: string | undefined;
  readonly errorMessage?: string | undefined;
  readonly upstreamRevoked?: boolean | undefined;
  readonly locallyRevoked?: boolean | undefined;
}

export interface ExitImpersonationResult {
  readonly exitedImpersonation: boolean;
  readonly upstreamExited: boolean;
}

export interface BffAuthConfig<TUser = UserInfo, TProfile = unknown> {
  readonly mode: 'bff';
  readonly bffBasePath?: string | undefined;
  readonly loginPath?: string | undefined;
  readonly logoutRedirectRoute?: string | undefined;
  readonly accountManagementEndpoint?: string | undefined;
  readonly defaultReturnTo?: string | undefined;
  readonly skipInitialFetch?: boolean | undefined;
  readonly initialSession?: BffSessionPayload<TUser, TProfile> | null | undefined;
  readonly mapSession?: ((rawData: Record<string, unknown>) => BffSessionPayload<TUser, TProfile>) | undefined;
  readonly fetchImpl?: typeof globalThis.fetch | undefined;
}

export type AuthProviderConfig<TUser = UserInfo, TProfile = unknown> =
  | OAuth2Config
  | BffAuthConfig<TUser, TProfile>;

export const STORAGE_KEYS = {
  ACCESS_TOKEN: 'witsauth_access_token',
  REFRESH_TOKEN: 'witsauth_refresh_token',
  TOKEN_EXPIRES_AT: 'witsauth_expires_at',
  TOKEN_TYPE: 'witsauth_token_type',
  SCOPE: 'witsauth_scope',
  ID_TOKEN: 'witsauth_id_token',
  CODE_VERIFIER: 'witsauth_code_verifier',
  STATE: 'witsauth_state',
  NONCE: 'witsauth_nonce',
  RETURN_TO: 'witsauth_return_to',
} as const;
