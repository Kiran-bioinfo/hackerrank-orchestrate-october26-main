"""
classifier.py — Multilingual deletion-intent classifier.

classify_intent(request_text) -> bool
  Returns True  if the text is an explicit personal-data / account deletion request.
  Returns False for marketing unsubscribes, data-export requests, corrections,
               general support questions, or any other non-deletion intent.

Approach:
  Rule-based keyword matching in 6 languages (EN, ES, FR, JA, PT, DE).
  Negative patterns are checked first to handle tricky false-positives
  (e.g. "send me my data but do NOT delete").
  No external network calls; fully deterministic.
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Positive intent: words/phrases that signal an explicit deletion request
# ---------------------------------------------------------------------------

_POSITIVE_PATTERNS: list[re.Pattern] = [
    # English
    re.compile(
        r'\b(delete|erase|remove|close|terminate|purge|wipe|destroy|cancel)\b'
        r'.{0,40}'
        r'\b(account|profile|data|record|information|personal|details|identity)\b',
        re.IGNORECASE,
    ),
    re.compile(
        r'\b(account|profile|data|record|information|personal|details)\b'
        r'.{0,40}'
        r'\b(delete|erase|removed?|closed?|terminated?|purged?)\b',
        re.IGNORECASE,
    ),
    re.compile(r'\b(permanently delete|account deletion|data deletion|right to erasure|'
               r'right to be forgotten|gdpr deletion|request.{0,10}deletion)\b', re.IGNORECASE),
    # Strong single-word deletion intents
    re.compile(r'\b(please delete|please erase|please remove|please close|please purge|'
               r'kindly delete|kindly erase|kindly remove)\b', re.IGNORECASE),
    re.compile(r'\b(delete (my|the|this|our)|erase (my|the|this)|remove (my|the|this))\b'
               r'.{0,30}\b(account|profile|data|information|records?|details?)\b', re.IGNORECASE),
    re.compile(r'\b(i (want|would like|need|request).{0,30}(delete|erase|remove|close|purge))\b',
               re.IGNORECASE),
    re.compile(r'\b(close (my|the|this) account)\b', re.IGNORECASE),
    re.compile(r'\b(erasure|suppression) (of|de).{0,20}(data|account|information)\b',
               re.IGNORECASE),

    # Spanish
    re.compile(r'\b(eliminar|borrar|suprimir|cerrar|cancelar|borrar).{0,40}'
               r'(cuenta|perfil|datos?|información|registros?)\b', re.IGNORECASE),
    re.compile(r'\b(eliminaci[oó]n|borrado|supresión).{0,30}(cuenta|datos?|perfil)\b',
               re.IGNORECASE),
    re.compile(r'\b(solicito|solicitar|quiero|quisiera|deseo|pido).{0,40}'
               r'(eliminar|borrar|suprimir|cerrar)\b', re.IGNORECASE),

    # French
    re.compile(r'\b(supprimer|effacer|fermer|supprimer|résilier|clôturer).{0,40}'
               r'(compte|profil|données|informations|enregistrement)\b', re.IGNORECASE),
    re.compile(r'\b(suppression|effacement|clôture).{0,30}(compte|données|profil)\b',
               re.IGNORECASE),
    re.compile(r'\b(je demande|je souhaite|je veux).{0,40}(supprimer|effacer|fermer)\b',
               re.IGNORECASE),
    re.compile(r'\b(suppression définitive|droit à l.effacement|droit à l.oubli)\b',
               re.IGNORECASE),

    # Japanese (deletion / account closure intent)
    re.compile(r'(アカウント|個人情報|データ|プロフィール).{0,20}(削除|消去|抹消|閉鎖|退会)'),
    re.compile(r'(削除|消去|抹消|閉鎖|退会).{0,20}(アカウント|個人情報|データ|プロフィール)'),
    re.compile(r'(削除を依頼|削除してください|削除をお願い|退会したい|アカウントを削除)'),
    re.compile(r'完全な削除|永久削除|削除リクエスト'),

    # Portuguese
    re.compile(r'\b(excluir|apagar|remover|fechar|cancelar).{0,40}'
               r'(conta|perfil|dados?|informações?|registros?)\b', re.IGNORECASE),
    re.compile(r'\b(exclusão|apagamento|remoção).{0,30}(conta|dados?|perfil)\b',
               re.IGNORECASE),

    # German
    re.compile(r'\b(löschen|entfernen|schließen|kündigen).{0,40}'
               r'(Konto|Profil|Daten|Informationen|Account)\b', re.IGNORECASE),
    re.compile(r'\b(Löschung|Löschanfrage|Datenlöschung|Kontolöschung)\b', re.IGNORECASE),

    # Generic: audit / deletion investigation phrasing
    re.compile(r'\b(permanently (delete|removed?|closed?|erased?))\b', re.IGNORECASE),
    re.compile(r'\b(full(y)? (deleted?|removed?|erased?))\b', re.IGNORECASE),

    # Audit / verification follow-up requests (still classify as deletion intent)
    re.compile(r'\b(verify|confirm|check|audit|investigate|inspect).{0,60}'
               r'(deleted?|removed?|erased?|gone|absent|closed?)\b', re.IGNORECASE),
    re.compile(r'\b(was|been|has been|have been).{0,30}'
               r'(deleted?|removed?|erased?|closed?)\b', re.IGNORECASE),
    re.compile(r'\b(account|profile|data).{0,30}'
               r'(still|traces|remains?|exists?|found|visible|appears?)\b.{0,30}'
               r'(delete|remove|erase|fix|handle|clean)', re.IGNORECASE),
    re.compile(r'\b(traces|ghost data|leftover|remaining.{0,20}(data|records?|copies))\b',
               re.IGNORECASE),
    re.compile(r'\b(please (audit|investigate|inspect|check|verify|confirm).{0,30}'
               r'(deletion|account|data|records?))\b', re.IGNORECASE),
    re.compile(r'\b(deletion.{0,30}(complete|finished|done|processed))\b', re.IGNORECASE),
    re.compile(r'\b(internal.{0,20}(deleted.account|tombstone|reference))\b', re.IGNORECASE),
    re.compile(r'\b(handle|manage|process|address).{0,30}'
               r'(deletion|removal|erasure|cleanup)\b', re.IGNORECASE),
    # "keep only the reference" / tombstone handling requests
    re.compile(r'\b(keep only|only (the|a) (reference|internal|stable))\b', re.IGNORECASE),
    # Requests asking to finish/complete/finalize deletion
    re.compile(r'\b(finish|complete|finalize|process).{0,30}'
               r'(deletion|removal|erasure|the (request|process))\b', re.IGNORECASE),
    # -ing deletion forms: "deleting my account", "removing my data", etc.
    re.compile(r'\b(deleting|removing|erasing|closing|terminating|purging)\b'
               r'.{0,60}\b(account|profile|data|information|record|detail|identifier)\b',
               re.IGNORECASE),
    re.compile(r'\b(account|profile|data|information|record|detail|identifier)\b'
               r'.{0,60}\b(deleting|removing|erasing|closed|deleted|removed|erased|terminated|purged)\b',
               re.IGNORECASE),
    # "remove that/this/the/my <thing>" patterns
    re.compile(r'\b(remove|delete|erase|close)\b\s+(that|this|the|my|our|the)\s+'
               r'(search|result|record|profile|account|data|copy|archive|export|entry)\b',
               re.IGNORECASE),
    # Broader audit/verify phrasing with longer distance
    re.compile(r'\b(verify|confirm|check|audit|investigate|inspect).{0,100}'
               r'(deleted?|removed?|erased?|gone|absent|closed?|complete)\b', re.IGNORECASE),
    re.compile(r'\b(was|been|has been|have been|is|are).{0,60}'
               r'(deleted?|removed?|erased?|closed?|gone|absent)\b', re.IGNORECASE),

    # Follow-up / verification requests that reference an already-submitted
    # deletion (e.g. "I deleted my account earlier, please confirm").
    re.compile(r'\b(deleted|erased|removed|closed|purged).{0,40}'
                r'(account|profile|data|information|record).{0,40}'
                r'(please.{0,20})?(confirm|check|verify|audit|investigate)\b',
                re.IGNORECASE),
    re.compile(r'\b(deleted|erased|removed|closed).{0,20}'
                r'(please.{0,15})?(confirm|check|verify|audit|investigate)\b',
                re.IGNORECASE),
    # Short verify/confirm + deletion noun (e.g. "verify deletion", "confirm deletion")
    re.compile(r'\b(verify|confirm|check|audit|inspect|ensure|make sure).{0,30}'
                r'(deletion|removal|erasure|account deletion|data deletion)\b',
                re.IGNORECASE),
    # "make sure my data is deleted" / "ensure my data has been removed"
    re.compile(r'\b(make sure|ensure).{0,20}'
                r'(my|the|this).{0,20}'
                r'(data|account|profile|information|record).{0,30}'
                r'(deleted?|removed?|erased?|closed?|purged?)\b', re.IGNORECASE),
    # "please check if my account is gone" / "check if my account is gone"
    re.compile(r'\b(check|verify|confirm|see).{0,20}'
                r'(if|whether).{0,20}'
                r'(my|the|this).{0,20}'
                r'(account|profile|data|information).{0,20}'
                r'(gone|deleted?|removed?|erased?|absent|closed?)\b', re.IGNORECASE),
    # "has my data been removed?" / "has my account been deleted?"
    re.compile(r'\b(has|have).{0,10}(my|the).{0,20}'
                r'(data|account|profile|information|record).{0,20}'
                r'(been).{0,15}(deleted?|removed?|erased?|closed?|purged?)\b',
                re.IGNORECASE),

    # --- Multilingual equivalents for follow-up / verification ---
    # Spanish
    re.compile(r'\b(verificar|confirmar|comprobar|auditar|revisar).{0,30}'
                r'(eliminaci[oó]n|borrado|supresi[oó]n|cuenta)\b', re.IGNORECASE),
    re.compile(r'\b(elimin[ae]|borrad[oa]|suprimid[oa]).{0,40}'
                r'(cuenta|datos?|perfil).{0,40}'
                r'(por favor.{0,15})?(confirmar|verificar|comprobar)\b', re.IGNORECASE),
    # French
    re.compile(r'\b(vérifier|confirmer|contrôler|auditer).{0,30}'
                r'(suppression|effacement|clôture|compte)\b', re.IGNORECASE),
    re.compile(r'\b(supprim[ée]|effac[ée]|clôtur[ée]).{0,40}'
                r'(compte|profil|données).{0,40}'
                r'(s.v.p.{0,15}|please.{0,15})?(confirmer|vérifier)\b', re.IGNORECASE),
    # German
    re.compile(r'\b(überprüfen|bestätigen|prüfen|überwachen).{0,30}'
                r'(Löschung|Löschanfrage|Kontolöschung|Konto)\b', re.IGNORECASE),
    re.compile(r'\b(gelöscht|entfernt|geschlossen).{0,40}'
                r'(Konto|Profil|Daten).{0,40}'
                r'(bitte.{0,15})?(bestätigen|überprüfen)\b', re.IGNORECASE),
    # Portuguese
    re.compile(r'\b(verificar|confirmar|auditar|revisar).{0,30}'
                r'(exclusão|excluiu|remoção|conta)\b', re.IGNORECASE),
    # Japanese
    re.compile(r'(削除|消去|抹消|閉鎖|退会).{0,30}(確認|検証|監査|完了)',
                re.IGNORECASE),
    re.compile(r'(確認|検証|監査).{0,30}(削除|消去|抹消|閉鎖|退会|アカウント)',
                re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Negative intent: phrases that explicitly EXCLUDE deletion intent
# The presence of these patterns alone is NOT disqualifying;
# they must be paired with the absence of any positive pattern,
# OR they contain clear do-NOT-delete language.
# ---------------------------------------------------------------------------

# Hard negatives: if matched, the request is NOT_APPLICABLE regardless of positives
_HARD_NEGATIVE_PATTERNS: list[re.Pattern] = [
    re.compile(r'\b(do not|don.t|please don.t|please do not)\s+(delete|erase|remove|close)\b',
               re.IGNORECASE),
    re.compile(r'\bdo NOT delete\b', re.IGNORECASE),
    re.compile(r'\bnot yet delete\b|\bnot delete yet\b', re.IGNORECASE),
    re.compile(r'\b(keep|retain|preserve) .{0,20}(account|data|profile) (active|open|intact)\b',
               re.IGNORECASE),
]

# Soft negatives: non-deletion requests without a positive signal → NOT_APPLICABLE
_NON_DELETION_PATTERNS: list[re.Pattern] = [
    # Data export / copy / download
    re.compile(r'\b(export|download|send|copy|give|provide|share).{0,30}'
               r'(my data|my information|my records|data copy|download)\b', re.IGNORECASE),
    re.compile(r'\b(portability|data portability|access request)\b', re.IGNORECASE),

    # Data correction / update
    re.compile(r'\b(correct|update|change|fix|amend|rectify).{0,30}'
               r'(my data|my information|my account|my details|my profile)\b', re.IGNORECASE),

    # Marketing / newsletter
    re.compile(r'\b(unsubscribe|opt.?out|stop (emails?|newsletters?|marketing|promotions?))\b',
               re.IGNORECASE),
    re.compile(r'\b(marketing (opt.?out|preferences?))\b', re.IGNORECASE),

    # General support / inquiry (without deletion intent)
    re.compile(r'\b(how (do|can) i|can you (help|tell)|what (is|are|happened))\b',
               re.IGNORECASE),
    re.compile(r'\b(billing question|order (status|issue|problem)|delivery|shipping|refund)\b',
               re.IGNORECASE),

    # Password / security (without deletion)
    re.compile(r'\b(reset.{0,10}password|password (reset|recovery|forgot))\b', re.IGNORECASE),
]


def classify_intent(request_text: str) -> bool:
    """Return True if *request_text* is an explicit deletion/erasure request.

    Logic:
      1. Empty text → False (NOT_APPLICABLE by default)
      2. Hard-negative match → False (explicit "do NOT delete" etc.)
      3. Any positive match → True
      4. Soft-negative match with no positive → False
      5. No match → False (conservative default)
    """
    if not request_text or not request_text.strip():
        return False

    text = request_text.strip()

    # Step 2: Hard negatives override everything
    for pat in _HARD_NEGATIVE_PATTERNS:
        if pat.search(text):
            logger.debug("HARD_NEGATIVE match: %s -> NOT_APPLICABLE", pat.pattern[:60])
            # Special case: if the text also contains strong deletion intent,
            # and the hard negative is about a *different* clause, still be conservative → False
            return False

    # Step 3: Check positive patterns
    for pat in _POSITIVE_PATTERNS:
        if pat.search(text):
            logger.debug("POSITIVE match: %s -> DELETION", pat.pattern[:60])
            return True

    # Step 4: Soft negatives (non-deletion request) → NOT_APPLICABLE
    for pat in _NON_DELETION_PATTERNS:
        if pat.search(text):
            logger.debug("NON_DELETION match: %s -> NOT_APPLICABLE", pat.pattern[:60])
            return False

    # Step 5: No signal found → conservative False
    logger.debug("No pattern matched for text (first 100 chars): %s", text[:100])
    return False


def classify_intent_explain(request_text: str) -> dict:
    """Classify intent and return a dict with result + matched patterns (for debugging)."""
    if not request_text or not request_text.strip():
        return {"is_deletion": False, "reason": "empty_text", "matched": []}

    text = request_text.strip()
    matched: list[str] = []

    for pat in _HARD_NEGATIVE_PATTERNS:
        if pat.search(text):
            return {
                "is_deletion": False,
                "reason": "hard_negative",
                "matched": [pat.pattern[:80]],
            }

    for pat in _POSITIVE_PATTERNS:
        if pat.search(text):
            matched.append(pat.pattern[:80])

    if matched:
        return {"is_deletion": True, "reason": "positive_match", "matched": matched}

    for pat in _NON_DELETION_PATTERNS:
        if pat.search(text):
            return {
                "is_deletion": False,
                "reason": "non_deletion",
                "matched": [pat.pattern[:80]],
            }

    return {"is_deletion": False, "reason": "no_match", "matched": []}
