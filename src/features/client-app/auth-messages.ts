export type AuthErrorKind = 'weak-password' | 'short-password' | 'same-password' | 'invalid-email' | 'credentials' | 'existing-account' | 'confirmation' | 'expired-link' | 'session' | 'rate-limit' | 'network' | 'unavailable' | 'unknown';

export const signupNotice = 'Se o cadastro puder ser concluído, você receberá um e-mail de confirmação. Confira sua caixa de entrada e o spam. Se precisar de ajuda, escreva para suporteadvexon@gmail.com.';
export const recoveryNotice = 'Se houver uma conta com este e-mail, enviamos um link para redefinir a senha. Se precisar de ajuda, escreva para suporteadvexon@gmail.com.';

export function authErrorKind(error: unknown): AuthErrorKind {
  const details = error && typeof error === 'object' ? error as { code?: unknown; message?: unknown; name?: unknown } : {};
  const code = typeof details.code === 'string' ? details.code : '';
  const text = typeof details.message === 'string' ? details.message : '';
  if (code === 'weak_password' || /weak password|password.*(weak|strength|pwned|compromised)|AuthWeakPasswordError/i.test(`${details.name ?? ''} ${text}`)) return 'weak-password';
  if (/password.*(at least|too short|minimum)|short password/i.test(text)) return 'short-password';
  if (code === 'same_password' || /same password|different.*password|password.*different/i.test(text)) return 'same-password';
  if (code === 'email_address_invalid' || code === 'validation_failed' && /email/i.test(text) || /invalid.*email|email.*invalid/i.test(text)) return 'invalid-email';
  if (code === 'invalid_credentials' || /invalid login|invalid credentials/i.test(text)) return 'credentials';
  if (['email_exists', 'user_already_exists'].includes(code) || /already.*registered|already.*exists/i.test(text)) return 'existing-account';
  if (code === 'email_not_confirmed' || /email.*not confirmed/i.test(text)) return 'confirmation';
  if (['otp_expired', 'otp_disabled', 'bad_code_verifier', 'flow_state_expired', 'flow_state_not_found'].includes(code) || /expired.*(link|token)|invalid.*(otp|token)/i.test(text)) return 'expired-link';
  if (['session_not_found', 'session_expired', 'refresh_token_not_found', 'refresh_token_already_used', 'bad_jwt', 'user_not_found'].includes(code) || /session.*(expired|missing)|auth session missing/i.test(text)) return 'session';
  if (['over_request_rate_limit', 'over_email_send_rate_limit', 'over_sms_send_rate_limit'].includes(code) || /rate limit|too many requests|after \d+ seconds/i.test(text)) return 'rate-limit';
  if (/failed to fetch|network|fetch failed|load failed/i.test(text)) return 'network';
  if (['signup_disabled', 'email_provider_disabled'].includes(code)) return 'unavailable';
  return 'unknown';
}

const messages: Record<AuthErrorKind, string> = {
  'weak-password': 'Esta senha é fraca ou fácil de adivinhar. Use uma senha mais longa e única, combinando letras maiúsculas e minúsculas, números e símbolos.',
  'short-password': 'A senha é muito curta. Use pelo menos 6 caracteres; o serviço pode exigir uma senha mais longa.',
  'same-password': 'A nova senha precisa ser diferente da atual.',
  'invalid-email': 'Informe um e-mail válido.',
  credentials: 'E-mail ou senha incorretos. Confira os dados e tente novamente.',
  'existing-account': signupNotice,
  confirmation: 'Confirme seu e-mail pelo link recebido antes de entrar. Confira também a pasta de spam.',
  'expired-link': 'Este link é inválido ou expirou. Solicite um novo link de recuperação de senha.',
  session: 'Sua sessão expirou ou não está disponível. Entre novamente ou solicite um novo link de recuperação.',
  'rate-limit': 'Muitas tentativas em pouco tempo. Aguarde alguns minutos e tente novamente.',
  network: 'Não foi possível conectar. Confira sua conexão e tente novamente.',
  unavailable: 'O acesso não está disponível no momento. Tente novamente mais tarde.',
  unknown: 'Não foi possível continuar. Tente novamente. Se o problema persistir, entre em contato com o atendimento.',
};

export function authErrorMessage(error: unknown): string {
  return messages[authErrorKind(error)];
}

type AuthFields = { name?: string; email?: string; password?: string; confirm?: string; minLength?: number };
export function validateAuthFields(fields: AuthFields): { field: string; message: string } | null {
  if (fields.name !== undefined && !fields.name.trim()) return { field: 'name', message: 'Informe seu nome.' };
  if (fields.email !== undefined && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(fields.email.trim())) return { field: 'email', message: 'Informe um e-mail válido.' };
  if (fields.password !== undefined && fields.password.length < (fields.minLength ?? 6)) return { field: 'password', message: `A senha deve ter pelo menos ${fields.minLength ?? 6} caracteres.` };
  if (fields.confirm !== undefined && fields.confirm !== fields.password) return { field: 'confirm', message: 'As senhas não coincidem.' };
  return null;
}

// Keep native browser-language bubbles disabled; focus and describe the invalid field instead.
export function validateAuthForm(form: HTMLFormElement, feedbackId: string): string | null {
  const inputs = Array.from(form.querySelectorAll<HTMLInputElement>('input[name]'));
  for (const input of inputs) { input.removeAttribute('aria-invalid'); input.removeAttribute('aria-describedby'); }
  const values: AuthFields = {};
  for (const input of inputs) {
    if (input.name === 'name' || input.name === 'email' || input.name === 'password' || input.name === 'confirm') values[input.name] = input.value;
    if (input.name === 'password' && input.minLength > 0) values.minLength = input.minLength;
  }
  const invalid = validateAuthFields(values);
  if (!invalid) return null;
  const input = inputs.find(item => item.name === invalid.field);
  input?.setAttribute('aria-invalid', 'true');
  input?.setAttribute('aria-describedby', feedbackId);
  input?.focus();
  return invalid.message;
}
