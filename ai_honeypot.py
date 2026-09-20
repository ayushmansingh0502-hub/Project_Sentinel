"""ai_honeypot.py - LLM-backed honeypot reply generator with safe fallback.

This module uses Google AI Studio when available; otherwise falls back to
the existing rule-based reply generator so the service can run without
the external SDK installed.
"""
import os
import logging
import importlib
from typing import List, Dict
from lifecycle import ScamPhase

# Setup logging
logger = logging.getLogger("honeypot.ai")

# Lazy/optional import of Google AI Studio
API_KEY = os.getenv("GOOGLE_AI_STUDIO_KEY", "")
genai = None
model = None
if API_KEY:
    try:
        genai = importlib.import_module("google.generativeai")
        genai.configure(api_key=API_KEY)
        try:
            model = genai.GenerativeModel('models/gemma-3-4b-it')
            logger.info("✅ Gemma model initialized successfully (gemma-3-4b-it)")
        except Exception as e:
            logger.error(f"❌ Model initialization failed: {e}")
            model = None
    except Exception:
        genai = None
        model = None
        logger.warning("⚠️ google.generativeai not available. Using rule-based replies.")


def generate_honeypot_reply(
    history: List[Dict],
    scam_type: str,
    phase: ScamPhase
) -> str:
    """
    Generates a believable honeypot reply based on
    scam lifecycle phase and conversation context.

    NOW USES LLM (Google AI Studio/Gemini) when API key is available.
    Falls back to rule-based responses if API is unavailable.
    """

    # Try LLM generation first if API key is available
    if model and API_KEY:
        try:
            logger.info(f"🤖 Attempting LLM reply generation (phase: {phase.value})")
            reply = _generate_llm_reply(history, scam_type, phase)
            logger.info(f"✅ LLM reply generated: {reply[:50]}...")
            return reply
        except Exception as e:
            logger.error(f"❌ LLM reply generation FAILED: {type(e).__name__}: {str(e)}")
            # Fall through to rule-based responses
    else:
        logger.warning(f"⚠️ LLM not available (model={model is not None}, API_KEY={API_KEY is not None})")

    # Fallback: Original rule-based logic
    logger.info("🔄 Using rule-based fallback reply")
    return _generate_rule_based_reply(history, scam_type, phase)


def _generate_llm_reply(
    history: List[Dict],
    scam_type: str,
    phase: ScamPhase
) -> str:
    """
    Generate contextual reply using Google AI Studio (Gemma).
    """
    # Build conversation context (last 5 messages)
    context_lines = []
    for msg in history[-5:]:
        role = "Scammer" if msg["role"] == "scammer" else "You (Victim)"
        context_lines.append(f"{role}: {msg['content']}")
    context = "\n".join(context_lines)
    
    # Extract the last scammer message to address it directly
    last_scammer_msg = ""
    for msg in reversed(history):
        if msg["role"] == "scammer":
            last_scammer_msg = msg["content"]
            break
    
    # Phase-specific guidance - MORE DIRECT & CONCRETE
    phase_guidance = {
        ScamPhase.INITIAL: "Respond addressing what they just said. Ask a specific clarifying question about it.",
        ScamPhase.PRESSURE: "React to the urgency mentioned. Show concern but ask practical questions about HOW to do it.",
        ScamPhase.PAYMENT: "Acknowledge the payment request. Ask specific questions about amount, method, or account details.",
        ScamPhase.ESCALATION: "React to the threat/consequences mentioned. Express concern and ask for alternatives or proof.",
        ScamPhase.EXIT: "Acknowledge what they said. Ask for time to check with family/bank, or request they call back later."
    }
    
    prompt = f"""You roleplay as a victim in a scam awareness training. The scammer just said:
"{last_scammer_msg}"

Your job: Generate a SHORT, REALISTIC victim response (1-2 sentences max) that:
1. DIRECTLY ADDRESSES what the scammer said (don't ignore their message)
2. Shows confusion or mild concern (typical victim behavior)
3. Asks SPECIFIC questions about THEIR request
4. Uses simple, natural language
5. Could be a WhatsApp/SMS message from an Indian non-tech-savvy person

GUIDELINES FOR THIS PHASE ({phase.value.upper()}):
- {phase_guidance.get(phase, 'Respond naturally')}
- If money/payment mentioned: ask HOW, WHERE, HOW MUCH specifically
- If account/verification mentioned: ask WHAT account, WHICH app, HOW to verify
- If threat/urgency mentioned: ask WHY urgent, WHAT happens if you don't
- Never deny having the thing they mentioned (don't say "I don't use electricity")
- Always acknowledge their message and add ONE specific question

CONVERSATION SO FAR:
{context}

Generate the victim's response (no quotes, no explanations):"""

    logger.info(f"📤 Sending prompt to Gemma (length: {len(prompt)} chars)")
    logger.info(f"📌 Last scammer message: '{last_scammer_msg}'")
    
    response = model.generate_content(
        prompt,
        generation_config=genai.GenerationConfig(
            temperature=0.7,  # Balanced - still natural but focused
            max_output_tokens=120
        )
    )
    
    logger.info(f"📥 Received response from Gemma")
    logger.info(f"Response text: '{response.text}'")
    
    reply = response.text.strip()
    logger.info(f"Stripped reply: '{reply}' (length: {len(reply)})")
    
    # Remove quotes if LLM wrapped the reply
    if reply.startswith('"') and reply.endswith('"'):
        reply = reply[1:-1]
    if reply.startswith("'") and reply.endswith("'"):
        reply = reply[1:-1]
    
    logger.info(f"Final reply after quote removal: '{reply}' (length: {len(reply)})")
    return reply


def _generate_rule_based_reply(
    history: List[Dict],
    scam_type: str,
    phase: ScamPhase
) -> str:
    """
    Original rule-based reply generation (fallback).
    """
    # Count scammer turns
    scammer_turns = len(
        [m for m in history if m["role"] == "scammer"]
    )

    last_message = history[-1]["content"].lower()

    # ---------------- INITIAL ----------------
    if phase == ScamPhase.INITIAL:
        return (
            "Sorry, I didn't really understand that. "
            "What exactly do I need to do?"
        )

    # ---------------- ESCALATION ----------------
    if phase == ScamPhase.ESCALATION:
        if "upi" in last_message or "pay" in last_message:
            return (
                "I tried paying but it's not going through. "
                "Can you send the details again?"
            )

        if "link" in last_message or "http" in last_message:
            return (
                "I'm not very comfortable clicking links. "
                "Is there another way to do this?"
            )

        return (
            "It's a bit confusing on my side. "
            "Can you explain it once more?"
        )

    # ---------------- PAYMENT ----------------
    if phase == ScamPhase.PAYMENT:
        if scam_type == "upi_fraud":
            return (
                "UPI keeps failing for me. "
                "Is there a bank account I can transfer to instead?"
            )

        return (
            "The payment option isn't working. "
            "What should I try next?"
        )

    # ---------------- MAX ESCALATION / EXIT ----------------
    if phase == ScamPhase.EXIT:
        if scammer_turns < 3:
            return (
                "It's still not working. "
                "Can you send the official confirmation message?"
            )

        return (
            "I don't want to make a mistake. "
            "Can you give me all the details clearly?"
        )

    # ---------------- FALLBACK ----------------
    return (
        "I'm trying to do this correctly. "
        "Please guide me step by step."
    )


# --- Security additions from master ---
import threading as _threading
import time as _time
import re as _re

_INJECTION_PATTERNS = _re.compile(
    r"ignore\s+(all\s+)?previous\s+instructions?|"
    r"you\s+are\s+now\s+a|"
    r"disregard\s+your\s+(system\s+)?prompt|"
    r"print\s+your\s+system\s+prompt|"
    r"reveal\s+(your\s+)?(api\s+)?key",
    _re.IGNORECASE
)
_llm_lock = _threading.Lock()
_llm_calls_this_minute = 0
_llm_last_reset = 0.0
_LLM_MAX_RPM = 15


def _llm_allowed() -> bool:
    global _llm_calls_this_minute, _llm_last_reset
    with _llm_lock:
        now = _time.time()
        if now - _llm_last_reset > 60:
            _llm_calls_this_minute = 0
            _llm_last_reset = now
        if _llm_calls_this_minute >= _LLM_MAX_RPM:
            return False
        _llm_calls_this_minute += 1
        return True


def _sanitize_for_prompt(text: str, max_len: int = 500) -> str:
    """Strip injection attempts and cap length before embedding in prompt."""
    if not text:
        return ""
    text = text[:max_len]
    if _INJECTION_PATTERNS.search(text):
        return "[message removed - policy violation]"
    return text
