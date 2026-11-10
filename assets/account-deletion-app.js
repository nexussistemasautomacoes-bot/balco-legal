// Fluxo externo de exclusão de conta — parte interativa (DOM + Supabase
// Auth real). Carregado só na página /exclusao-de-conta/, como
// `<script type="module">`, DEPOIS de account-deletion-logic.js (script
// clássico, expõe as funções puras em `window`).
//
// Biblioteca externa justificada (única exceção às 3 páginas puramente
// estáticas/sem script desta linha de trabalho): reimplementar PKCE à mão
// (geração de code_verifier/challenge, troca de código por sessão) seria
// mais arriscado que carregar a MESMA biblioteca (`@supabase/supabase-js`,
// já auditada e usada pelo próprio app) de um CDN com versão travada,
// idêntica à instalada no projeto (`package.json`, 2.116.0) — nunca
// `@latest`.
//
// SEGURANÇA (ver tests/accountDeletionAppScript.test.ts para os
// invariantes verificados por leitura estática do código-fonte real):
// - `shouldCreateUser: false` sempre, nunca cria conta nova por aqui.
// - `emailRedirectTo` é SEMPRE a própria página (buildSelfRedirectUrl) —
//   nunca um parâmetro de URL controlado por quem clicou o link.
// - Mensagem de "link enviado" é SEMPRE a mesma genérica
//   (classifyOtpRequestOutcome/messageForOtpOutcome), nunca revela se a
//   conta existe.
// - `code` da URL é removido (`history.replaceState`) assim que lido —
//   nunca permanece na barra de endereço/histórico do navegador.
// - Nenhum e-mail, token, código ou sessão é passado para `console.*` em
//   nenhum caminho deste arquivo.
// - Consulta de status nunca filtra por um `user_id` vindo do cliente —
//   depende inteiramente da policy RLS `account_deletion_requests_select`
//   (`user_id = auth.uid()`, migration 0016), confirmada viva nesta
//   rodada (`has_table_privilege('authenticated', ...)` = true).
// - A chamada de exclusão nunca envia um corpo com `userId` — exatamente
//   como a Edge Function `request-account-deletion` já exige (ela só usa
//   `auth.getUser()` do próprio JWT, nunca um campo do corpo).
// - Sessão NUNCA persiste em localStorage entre recarregamentos
//   (`persistSession: false`) — vive só na memória desta página, pelo
//   tempo mínimo necessário, e é encerrada explicitamente
//   (`auth.signOut()`) assim que o fluxo termina (sucesso, bloqueio, falha
//   OU consulta de status) — nunca deixada aberta "por via das dúvidas".
// - Link de confirmação aberto num navegador/aparelho diferente daquele
//   que o solicitou é detectado especificamente (`AuthPKCECodeVerifierMissingError`,
//   investigado contra o SDK real instalado) e recebe uma mensagem própria,
//   acionável — nunca confundido com "link genuinamente expirado".

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.116.0';

function byId(id) {
  return document.getElementById(id);
}

function setStatusText(el, text) {
  // textContent, nunca innerHTML — entrada do usuário (e-mail) nunca vira HTML.
  el.textContent = text;
}

async function main() {
  const supabaseUrl = window.__BALCO_SUPABASE_URL__;
  const supabaseKey = window.__BALCO_SUPABASE_PUBLISHABLE_KEY__;
  const root = byId('account-deletion-app');
  if (!root) return;

  if (!supabaseUrl || !supabaseKey) {
    setStatusText(byId('ad-form-message'), 'Este formulário não está configurado nesta cópia da página. Use a exclusão dentro do aplicativo.');
    return;
  }

  const supabaseClient = createClient(supabaseUrl, supabaseKey, {
    // persistSession:false — sessão vive só na memória desta página, nunca
    // em localStorage entre recarregamentos; cada etapa abaixo encerra a
    // sessão (signOut) assim que termina de usá-la.
    auth: { flowType: 'pkce', detectSessionInUrl: false, persistSession: false },
  });

  const emailStep = byId('ad-step-email');
  const confirmStep = byId('ad-step-confirm');
  const resultStep = byId('ad-step-result');
  const form = byId('ad-email-form');
  const emailInput = byId('ad-email-input');
  const formMessage = byId('ad-form-message');
  const submitButton = byId('ad-submit-button');
  const confirmButton = byId('ad-confirm-button');
  const confirmMessage = byId('ad-confirm-message');
  const resultMessage = byId('ad-result-message');
  const statusButton = byId('ad-status-button');

  function showStep(step) {
    for (const el of [emailStep, confirmStep, resultStep]) {
      if (el) el.hidden = el !== step;
    }
  }

  // --- Retomada de um magic link (?code=...) ---
  const code = extractPkceCodeFromSearch(window.location.search);
  if (code) {
    // Remove o código da URL IMEDIATAMENTE — nunca fica na barra de
    // endereço, histórico ou num possível compartilhamento acidental da
    // URL depois.
    window.history.replaceState({}, document.title, window.location.pathname);
    setStatusText(confirmMessage, 'Confirmando seu acesso...');
    showStep(confirmStep);
    const { error } = await supabaseClient.auth.exchangeCodeForSession(code);
    if (error) {
      setStatusText(confirmMessage, messageForCodeExchangeError(classifyCodeExchangeError(error)));
      if (confirmButton) confirmButton.hidden = true;
      return;
    }
    setStatusText(
      confirmMessage,
      'Identidade confirmada. Revise as informações abaixo antes de confirmar a exclusão — esta ação não pode ser desfeita automaticamente.',
    );
  }

  // --- Passo 1: pedir o e-mail ---
  let cooldownUntil = 0;
  if (form) {
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const email = emailInput.value;
      if (!isValidEmailFormat(email)) {
        setStatusText(formMessage, 'Digite um e-mail válido.');
        return;
      }
      if (Date.now() < cooldownUntil) {
        setStatusText(formMessage, messageForOtpOutcome('rate_limited'));
        return;
      }
      submitButton.disabled = true;
      setStatusText(formMessage, 'Enviando...');
      const { error } = await supabaseClient.auth.signInWithOtp({
        email: email.trim(),
        options: {
          shouldCreateUser: false,
          emailRedirectTo: buildSelfRedirectUrl(window.location.href),
        },
      });
      const outcome = classifyOtpRequestOutcome(error);
      setStatusText(formMessage, messageForOtpOutcome(outcome));
      // Cooldown de UX (60s) — camada extra de defesa contra reenvio
      // acidental em loop; o limite real de abuso é aplicado pelo próprio
      // GoTrue do lado do servidor, fora do alcance deste script estático.
      cooldownUntil = Date.now() + 60_000;
      setTimeout(() => {
        submitButton.disabled = false;
      }, 60_000);
    });
  }

  // --- Passo 2: confirmação explícita antes de registrar o pedido ---
  if (confirmButton) {
    confirmButton.addEventListener('click', async () => {
      confirmButton.disabled = true;
      setStatusText(confirmMessage, 'Processando...');
      const {
        data: { session },
      } = await supabaseClient.auth.getSession();
      if (!session) {
        setStatusText(confirmMessage, 'Sua verificação expirou. Volte e solicite um novo link.');
        return;
      }
      try {
        const response = await fetch(`${supabaseUrl}/functions/v1/request-account-deletion`, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${session.access_token}`,
            apikey: supabaseKey,
          },
        });
        const body = await response.json().catch(() => ({}));
        showStep(resultStep);
        if (body && typeof body.status === 'string') {
          setStatusText(resultMessage, formatDeletionStatusMessage(body.status));
        } else {
          setStatusText(resultMessage, 'Não foi possível confirmar o resultado agora. Use "Consultar status" para verificar depois.');
        }
      } catch {
        showStep(resultStep);
        setStatusText(resultMessage, 'Não foi possível concluir agora. Tente novamente em instantes.');
      } finally {
        // Encerramento seguro: a sessão desta página nunca continua viva
        // depois que o fluxo terminou, com sucesso ou não.
        await supabaseClient.auth.signOut();
      }
    });
  }

  // --- Consultar status (sempre autenticado; RLS restringe à própria linha, nunca um filtro de user_id vindo do cliente) ---
  if (statusButton) {
    statusButton.addEventListener('click', async () => {
      const {
        data: { session },
      } = await supabaseClient.auth.getSession();
      if (!session) {
        setStatusText(resultMessage, 'Confirme seu e-mail primeiro para consultar o status.');
        showStep(resultStep);
        return;
      }
      // NUNCA encerra a sessão aqui (diferente do passo de confirmação,
      // que é terminal por natureza): quem consulta o status pode ainda
      // querer clicar em "Confirmar exclusão" logo em seguida, na mesma
      // visita — derrubar a sessão nesse meio-tempo quebraria esse
      // caminho sem necessidade de segurança real (persistSession:false
      // já garante que a sessão nunca sobrevive a um recarregamento/nova
      // aba de qualquer forma).
      const { data, error } = await supabaseClient
        .from('account_deletion_requests')
        .select('status')
        .maybeSingle();
      showStep(resultStep);
      if (error || !data) {
        setStatusText(resultMessage, 'Nenhuma solicitação encontrada para esta conta ainda.');
        return;
      }
      setStatusText(resultMessage, formatDeletionStatusMessage(data.status));
    });
  }

  if (!code) showStep(emailStep);
}

main();
