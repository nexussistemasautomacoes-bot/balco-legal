// Lógica PURA do fluxo externo de exclusão de conta — sem DOM, sem rede,
// sem Supabase. Carregado como <script> clássico no navegador (funções
// viram globais, sem módulo) E via require() nos testes
// (tests/accountDeletionLogic.test.ts) — mesmo arquivo, nunca duas cópias
// do mesmo texto/regra.
//
// Princípio de segurança central deste arquivo (rodada "FINALIZAR
// EXCLUSÃO DE CONTA WEB"): nenhuma função aqui pode, para NENHUM caminho
// de entrada, produzir uma mensagem que revele se um e-mail tem ou não
// conta no Balcô — nem por sucesso, nem por erro.

/** Validação de FORMATO só — nunca uma consulta de existência. */
function isValidEmailFormat(email) {
  if (typeof email !== 'string') return false;
  const trimmed = email.trim();
  // Regex deliberadamente simples (RFC 5322 completo é desnecessário aqui
  // — o GoTrue já valida de verdade do lado do servidor; isto é só uma
  // checagem de UX antes de gastar uma tentativa).
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed);
}

/**
 * Classifica o resultado de `signInWithOtp` em só 2 buckets, nenhum dos
 * dois revelando se a conta existe:
 * - 'sent': mostrar sempre a MESMA mensagem genérica de sucesso — cobre
 *   tanto o sucesso real quanto o erro que o GoTrue devolve com
 *   `shouldCreateUser:false` para um e-mail sem conta (ex.: "Signups not
 *   allowed for otp"). Do ponto de vista de quem está do lado de fora,
 *   as duas situações são estruturalmente indistinguíveis — e devem
 *   continuar assim na UI.
 * - 'rate_limited': pedir para tentar mais tarde — não revela existência
 *   (o rate limit do GoTrue age por e-mail/IP independente de a conta
 *   existir).
 * - 'infra_error': falha de rede/infra genuína — mensagem genérica,
 *   nunca ecoa o texto de erro bruto do servidor (que poderia, em algum
 *   caso futuro, vir a mencionar algo específico).
 */
function classifyOtpRequestOutcome(error) {
  if (!error) return 'sent';
  const status = typeof error.status === 'number' ? error.status : null;
  if (status === 429) return 'rate_limited';
  // Qualquer erro 4xx de validação (inclusive "signups not allowed",
  // "user not found" em variações futuras da API) cai no mesmo bucket
  // de sucesso aparente — nunca diferenciado na UI.
  if (status !== null && status >= 400 && status < 500) return 'sent';
  return 'infra_error';
}

const GENERIC_LINK_SENT_MESSAGE =
  'Se existir uma conta do Balcô com este e-mail, enviamos um link de confirmação para ela. Confira sua caixa de entrada (e o spam) e clique no link para continuar.';
const RATE_LIMITED_MESSAGE = 'Muitas tentativas em pouco tempo. Aguarde alguns minutos antes de tentar de novo.';
const INFRA_ERROR_MESSAGE = 'Não foi possível enviar o link agora. Tente novamente em instantes.';

function messageForOtpOutcome(outcome) {
  if (outcome === 'rate_limited') return RATE_LIMITED_MESSAGE;
  if (outcome === 'infra_error') return INFRA_ERROR_MESSAGE;
  return GENERIC_LINK_SENT_MESSAGE;
}

/**
 * `emailRedirectTo` é SEMPRE a própria página atual (origin + pathname,
 * nunca query/hash) — nunca um valor lido de um parâmetro da URL (isso
 * seria um open-redirect: um link malicioso poderia tentar mandar o
 * magic link de volta para um destino controlado por um atacante).
 */
function buildSelfRedirectUrl(hrefOrLocation) {
  const url = new URL(typeof hrefOrLocation === 'string' ? hrefOrLocation : hrefOrLocation.href);
  url.search = '';
  url.hash = '';
  return url.toString();
}

/** Extrai só `code` da query string (PKCE) — nunca lê `redirect_to`/`next`/qualquer outro parâmetro para decidir destino. */
function extractPkceCodeFromSearch(search) {
  const params = new URLSearchParams(search || '');
  return params.get('code');
}

/**
 * Classifica o erro de `exchangeCodeForSession` — investigado contra o
 * SDK real instalado (`node_modules/@supabase/auth-js`, versão 2.116.0):
 * um link aberto num navegador/aparelho DIFERENTE daquele que pediu o
 * magic link lança especificamente `AuthPKCECodeVerifierMissingError`
 * (`code: 'pkce_code_verifier_not_found'`) — o `code_verifier` do PKCE
 * mora só no `localStorage` do navegador que originou o pedido, nunca é
 * enviado para lugar nenhum. Distinguir esse caso (mensagem acionável: "
 * abra no mesmo navegador") de um link genuinamente expirado/reutilizado
 * (qualquer outro erro) melhora a experiência sem revelar nada sensível —
 * nenhum dos dois casos indica se a conta existe.
 */
function classifyCodeExchangeError(error) {
  if (!error) return null;
  if (error.code === 'pkce_code_verifier_not_found') return 'verifier_missing';
  return 'invalid_or_expired';
}

const VERIFIER_MISSING_MESSAGE =
  'Não encontramos a verificação desta solicitação neste navegador. Abra o link de confirmação no MESMO navegador e no MESMO aparelho em que você clicou em "Enviar link de confirmação", ou solicite um novo link.';
const INVALID_OR_EXPIRED_MESSAGE = 'Este link é inválido ou já expirou. Volte e solicite um novo.';

function messageForCodeExchangeError(classification) {
  if (classification === 'verifier_missing') return VERIFIER_MISSING_MESSAGE;
  return INVALID_OR_EXPIRED_MESSAGE;
}

/**
 * Mensagens para os 5 estados reais de `account_deletion_requests.status`
 * (migration 0018) — nunca um 6º estado inventado; estado desconhecido
 * cai no fallback explícito, nunca assume "deu certo".
 */
const DELETION_STATUS_MESSAGES = {
  requested: 'Sua solicitação foi registrada e será processada em instantes.',
  processing: 'Sua solicitação está sendo processada agora.',
  completed: 'Sua conta foi excluída com sucesso.',
  blocked_pending_business_resolution:
    'Você é proprietário de um estabelecimento ativo. Antes de excluir sua conta, é preciso transferir a titularidade para outra pessoa da equipe ou solicitar o encerramento do estabelecimento — pelo próprio aplicativo.',
  failed: 'Não foi possível concluir a exclusão por um erro técnico. Tente novamente; se persistir, use o aplicativo.',
};

function formatDeletionStatusMessage(status) {
  return DELETION_STATUS_MESSAGES[status] || 'Estado da solicitação desconhecido — tente novamente mais tarde.';
}

const EXPORTS = {
  isValidEmailFormat,
  classifyOtpRequestOutcome,
  messageForOtpOutcome,
  buildSelfRedirectUrl,
  extractPkceCodeFromSearch,
  formatDeletionStatusMessage,
  classifyCodeExchangeError,
  messageForCodeExchangeError,
  GENERIC_LINK_SENT_MESSAGE,
  RATE_LIMITED_MESSAGE,
  INFRA_ERROR_MESSAGE,
  VERIFIER_MISSING_MESSAGE,
  INVALID_OR_EXPIRED_MESSAGE,
  DELETION_STATUS_MESSAGES,
};

// UMD-lite: script clássico no navegador (globais em window), CommonJS no
// Node/Jest — nunca duas cópias da mesma lógica.
if (typeof module !== 'undefined' && module.exports) {
  module.exports = EXPORTS;
} else if (typeof window !== 'undefined') {
  Object.assign(window, EXPORTS);
}
