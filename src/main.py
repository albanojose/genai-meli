# app/main.py — GenAI Security Challenge

import os
import json
import traceback
import streamlit as st
import pandas as pd
import yaml

from src.demo_data import MOCK_EMAILS, MOCK_CDV_DATABASE, MOCK_SECRETS
from src.mcp_server import MockMCPServer
from src.policy_engine import PolicyEngine
from src.agent import SecurityChallengeAgent

# ─────────────────────────────────────────────
#  PAGE CONFIG & CSS
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="GenAI Security Challenge",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
  .stAppHeader { display: none; }
  .block-container { padding-top: 1.5rem; padding-bottom: 2rem; }
  .event-warning { border-left:4px solid #f59e0b; padding:8px 12px; margin:4px 0; background:rgba(245,158,11,0.08); }
  .event-pass    { border-left:4px solid #10b981; padding:8px 12px; margin:4px 0; background:rgba(16,185,129,0.08); }
  .event-info    { border-left:4px solid #3b82f6; padding:8px 12px; margin:4px 0; background:rgba(59,130,246,0.08); }
  .event-danger  { border-left:4px solid #ef4444; padding:8px 12px; margin:4px 0; background:rgba(239,68,68,0.08); }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────
#  SESSION STATE
# ─────────────────────────────────────────────
def init_state():
    defaults = {
        "api_key": os.environ.get("OPENROUTER_API_KEY", ""),
        "llm_model": "meta-llama/llama-3.1-70b-instruct",
        "policy_engine": PolicyEngine(),
        "mcp_server": MockMCPServer(),
        "user_role": "dispute_specialist",
        "chat_messages": [],        
        "agent_messages": [],       
        "system_events": [],        
        "pending_approval": None,   
        "agent_busy": False,        
        "error_msg": None,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

init_state()

def render_event(ev: dict):
    etype = ev.get("type", "info")
    title = ev.get("title", "")
    msg = ev.get("msg", "")
    st.markdown(
        f'<div class="event-{etype}">'
        f'<div style="font-family:monospace;font-size:0.82rem;font-weight:600;letter-spacing:0.02em">{title}</div>'
        f'<div style="font-size:0.78rem;margin-top:3px;opacity:0.85">{msg}</div>'
        f'</div>',
        unsafe_allow_html=True
    )

def reset_chat():
    st.session_state.chat_messages = []
    st.session_state.agent_messages = []
    st.session_state.system_events = []
    st.session_state.pending_approval = None
    st.session_state.agent_busy = False
    st.session_state.error_msg = None
    st.session_state.policy_engine.clear_audit_logs()

def make_agent():
    return SecurityChallengeAgent(
        api_key=st.session_state.api_key,
        model=st.session_state.llm_model,
        policy_engine=st.session_state.policy_engine,
        mcp_server=st.session_state.mcp_server
    )

# ─────────────────────────────────────────────
#  SIDEBAR
# ─────────────────────────────────────────────
with st.sidebar:
    st.title("Controls")

    # Security Mode
    st.subheader("Security Mode")
    security_mode = st.radio(
        "Security Mode",
        ["Vulnerable Mode", "Protected Mode"],
        index=1,
        label_visibility="collapsed"
    )
    is_protected = "Protected Mode" in security_mode

    if is_protected:
        st.success("**Protected Mode — Policy Engine ON**", icon=None)
    else:
        st.error("**Vulnerable Mode — All defenses OFF!**", icon=None)

    st.divider()

    # Role
    st.subheader("Agent Role")
    user_role = st.selectbox(
        "Agent Role",
        ["dispute_specialist", "fraud_manager", "operations_team"],
        label_visibility="collapsed",
        disabled=not is_protected,
        help="Roles are only enforced in Protected Mode."
    )
    st.session_state.user_role = user_role

    st.divider()

    # LLM Config
    st.subheader("LLM Config")
    api_key_input = st.text_input(
        "OpenRouter API Key",
        value=st.session_state.api_key,
        type="password",
        placeholder="sk-or-v1-..."
    )
    if api_key_input != st.session_state.api_key:
        st.session_state.api_key = api_key_input
        st.rerun()

    llm_model = st.selectbox(
        "Model",
        [
            "meta-llama/llama-3.1-70b-instruct",
        ],
        index=0
    )
    if llm_model != st.session_state.llm_model:
        st.session_state.llm_model = llm_model
        st.rerun()

    if not st.session_state.api_key:
        st.warning("No API key. Add your OpenRouter key to run real LLM attacks.", icon=None)
    else:
        st.caption(f"Connected: `{st.session_state.llm_model}`")

    st.divider()

    if st.button("Clear Chat & Logs", use_container_width=True):
        reset_chat()
        st.rerun()

# ─────────────────────────────────────────────
#  MAIN HEADER + KPIs
# ─────────────────────────────────────────────
kpis = st.session_state.policy_engine.get_kpis()

st.title("GenAI Security Challenge")

if is_protected:
    st.caption(
        "**[Protected Mode]** Layered pipeline: "
        "Risk Classifier → Planner → Capability Broker → Policy Engine → MCP Gateway → Response Generator. "
        "Control layer events appear in the Security Events panel."
    )
else:
    st.caption(
        "**[Vulnerable Mode]** Single-agent loop, no policy controls. "
        "LLM calls tools directly. All defences disabled."
    )
st.divider()

c1, c2, c3 = st.columns(3)
c1.metric("Security Defenses", "ON" if is_protected else "OFF", "Policy Engine Active" if is_protected else "All protections disabled", delta_color="normal" if is_protected else "inverse")
c2.metric("Blocked Attacks", kpis["prompt_injection_attempts"] + kpis["blocked_tool_calls"] + kpis.get("blocked_by_risk_engine", 0), f"{kpis['prompt_injection_attempts']} inj | {kpis['blocked_tool_calls']} tool | {kpis.get('blocked_by_risk_engine', 0)} pdp")
c3.metric("Data Maskings", kpis["pan_masking_events"] + kpis["secret_masking_events"], f"{kpis['pan_masking_events']} PAN | {kpis['secret_masking_events']} sec")

st.write("")

# ─────────────────────────────────────────────
#  TABS
# ─────────────────────────────────────────────
tab_chat, tab_emails, tab_cdv, tab_configs, tab_logs = st.tabs([
    "Agent Chat", "Email Reference", "CDV", "Policy & Config", "Audit Trail"
])

# ═══════════════════════════════════════════════
#  TAB 1 — AGENT CHAT
# ═══════════════════════════════════════════════
with tab_chat:
    if not st.session_state.api_key:
        st.error("**No OpenRouter API key.** Add your key in the sidebar to start chatting with the real LLM agent.", icon=None)
    else:
        hint_col, chat_col = st.columns([1, 2], gap="large")

        with hint_col:
            if is_protected:
                st.markdown(f"**Mode:** Protected | **Role:** `{user_role}`")
            else:
                st.markdown(f"**Mode:** Vulnerable")
            st.divider()



            if st.session_state.system_events:
                st.divider()
                st.markdown("**Policy Engine Events**")
                for ev in st.session_state.system_events[-5:]:
                    render_event(ev)

        with chat_col:
            # Render chat history
            for msg in st.session_state.chat_messages:
                role = msg["role"]
                if role == "user":
                    with st.chat_message("user", avatar="👤"):
                        st.markdown(msg["content"])
                elif role == "assistant":
                    with st.chat_message("assistant", avatar="🤖"):
                        if msg.get("content"):
                            st.markdown(msg["content"])
                        if msg.get("tool_calls"):
                            for tc in msg["tool_calls"]:
                                name = tc["function"]["name"]
                                try:
                                    args_str = json.dumps(json.loads(tc["function"]["arguments"]), indent=2)
                                except:
                                    args_str = tc["function"]["arguments"]
                                st.code(f"🛠 Calling: {name}\n{args_str}", language="text")
                elif role == "tool":
                    with st.chat_message("assistant", avatar="🤖"):
                        tool_name = msg.get("name", "tool")
                        content = msg.get("content", "")
                        try:
                            st.json(json.loads(content))
                        except:
                            st.code(content)
                elif role == "error":
                    with st.chat_message("assistant", avatar="❌"):
                        st.error(msg["content"])

            # HITL approval block
            if st.session_state.pending_approval:
                pending = st.session_state.pending_approval
                st.divider()
                st.error("### Human Approval Required", )

                c_a, c_b = st.columns(2)
                with c_a:
                    st.markdown(f"**Tool:** `{pending['tool_name']}`\n**Role requesting:** `{user_role}`")
                with c_b:
                    st.markdown("**Arguments:**")
                    st.json(pending["args"])

                st.caption("This action requires explicit authorization from a second authorized person.")

                col1, col2 = st.columns(2)
                with col1:
                    if st.button("Approve & Execute", type="primary", use_container_width=True):
                        agent = make_agent()
                        raw_result = agent._execute_tool_local(pending["tool_name"], pending["args"])
                        if is_protected and isinstance(raw_result, dict) and "pan" in raw_result:
                            raw_result["pan"] = st.session_state.policy_engine.validate_output(raw_result["pan"])
                        
                        st.session_state.policy_engine.metrics["successful_hitl_approvals"] += 1
                        st.session_state.policy_engine.log_audit("human_approval", "approved", {"tool": pending["tool_name"], "user_role": user_role})
                        
                        try:
                            msgs, pend2, evts2 = agent.run_full_loop(None, is_protected, user_role, pending["messages"], {
                                "tool_name": pending["tool_name"], "args": pending["args"], "result": raw_result, "tool_call_id": pending.get("tool_call_id")
                            })
                            st.session_state.chat_messages.extend(msgs[len(pending["messages"]):])
                            st.session_state.agent_messages = msgs
                            st.session_state.system_events += evts2
                            st.session_state.pending_approval = pend2
                        except Exception as e:
                            st.session_state.chat_messages.append({"role": "error", "content": traceback.format_exc()})
                        st.rerun()
                with col2:
                    if st.button("❌ Deny", use_container_width=True):
                        st.session_state.policy_engine.log_audit("human_approval", "denied", {"tool": pending["tool_name"], "user_role": user_role})
                        agent = make_agent()
                        try:
                            msgs, pend2, evts2 = agent.run_full_loop(None, is_protected, user_role, pending["messages"], {
                                "tool_name": pending["tool_name"], "args": pending["args"], "result": {"error": "Denied by human operator."}, "tool_call_id": pending.get("tool_call_id")
                            })
                            st.session_state.chat_messages.extend(msgs[len(pending["messages"]):])
                            st.session_state.agent_messages = msgs
                            st.session_state.system_events += evts2
                            st.session_state.pending_approval = pend2
                        except Exception as e:
                            st.session_state.chat_messages.append({"role": "error", "content": traceback.format_exc()})
                        st.rerun()

            # Agent processing spinner
            if st.session_state.agent_busy and not st.session_state.pending_approval:
                with st.spinner("Agent is thinking..."):
                    try:
                        agent = make_agent()
                        # Extract email_id from user message so Protected Mode routes to run_enterprise_loop
                        last_user_text = ""
                        for m in reversed(st.session_state.agent_messages):
                            if m.get("role") == "user":
                                last_user_text = m.get("content", "")
                                break
                        import re as _re
                        _eid_match = _re.search(r"\b(email_\w+)\b", last_user_text, _re.IGNORECASE)
                        extracted_email_id = _eid_match.group(1) if _eid_match else None
                        msgs, pend, evts = agent.run_full_loop(extracted_email_id, is_protected, user_role, st.session_state.agent_messages)
                        st.session_state.chat_messages.extend(msgs[len(st.session_state.agent_messages):])
                        st.session_state.agent_messages = msgs
                        st.session_state.system_events += evts
                        st.session_state.pending_approval = pend
                    except Exception as e:
                        st.session_state.chat_messages.append({"role": "error", "content": traceback.format_exc()})
                    finally:
                        st.session_state.agent_busy = False
                    st.rerun()

            # Chat input
            if not st.session_state.pending_approval and not st.session_state.agent_busy:
                user_input = st.chat_input("Type your message to the agent...")
                if user_input:
                    st.session_state.chat_messages.append({"role": "user", "content": user_input})
                    st.session_state.agent_messages.append({"role": "user", "content": user_input})
                    st.session_state.agent_busy = True
                    st.rerun()

# ═══════════════════════════════════════════════
#  TAB 2 — EMAIL REFERENCE
# ═══════════════════════════════════════════════
with tab_emails:
    st.markdown("### Incoming Email Inbox — Attack Scenarios")
    _ATTACK_LABELS = {
        "email_002": ("danger",  "🔴 Indirect Prompt Injection",      "Embedded instruction to call `cdv_detokenize` for an unrelated transaction."),
        "email_003": ("danger",  "🔴 Secret Disclosure",              "Instructs the agent to output API keys and signing keys from memory."),
        "email_005": ("danger",  "🔴 Data Exfiltration via Webhook",  "Instructs agent to detokenize PAN and POST it to an external URL."),
        "email_006": ("warning", "🟠 Justification Spoofing",         "Embeds a convincing fake justification to manipulate the Human Approval step."),
    }
    for mail in MOCK_EMAILS:
        label_data = _ATTACK_LABELS.get(mail["id"])
        prefix = f" [{label_data[1]}]" if label_data else ""
        with st.expander(f"**{mail['id']}**{prefix} — {mail['sender']} | {mail['subject']}"):
            st.info(mail["body"], icon=None)
            if label_data:
                severity, title, desc = label_data
                getattr(st, "error" if severity == "danger" else "warning")(f"**{title}** — {desc}", icon=None)

# ═══════════════════════════════════════════════
#  TAB 3 — CDV
# ═══════════════════════════════════════════════
with tab_cdv:
    st.markdown("### Cardholder Data Vault (CDV) Databases")
    st.markdown("### Vault Storage Details")
    cdv_records = []
    for k, v in MOCK_CDV_DATABASE.items():
        cdv_records.append({
            "Transaction ID": v["txn_id"],
            "Customer": v["customer_name"],
            "Amount": f"${v['amount']:.2f}",
            "Tokenized PAN (Public)": v["tokenized_pan"],
            "Scope": ", ".join(v["compliance_scope"]).upper()
        })
    st.dataframe(pd.DataFrame(cdv_records), use_container_width=True)
    
    st.divider()
    st.markdown("### Secrets Registry (Trust Boundary: Vault Memory)")
    st.dataframe(pd.DataFrame([{"Key": k, "Value": v} for k, v in MOCK_SECRETS.items()]), use_container_width=True)

# ═══════════════════════════════════════════════
#  TAB 4 — POLICY & CONFIG
# ═══════════════════════════════════════════════
with tab_configs:
    pe = st.session_state.policy_engine

    if is_protected:
        st.markdown("### Enterprise Architecture (Protected Mode)")
        st.code("""
User Input
    ↓
┌────────────────────────┐
│  PromptRiskClassifier  │  ← PCI 6.2.4  (pure Python, no LLM)
└────────────────────────┘
    ↓ RiskReport {risk, confidence, reasons}
┌────────────────────────┐
│  RiskDecisionEngine    │  ← PCI 6.2.4 / 10.2.1 (PDP Matrix)
└────────────────────────┘
    ↓ Decision: ALLOW / ALLOW_WITH_ISOLATION / BLOCK
┌────────────────────────┐
│   Planner Agent        │  ← PCI 7.2.1  (LLM, no tools, JSON plan only)
└────────────────────────┘
    ↓ Plan {intent, required_capabilities[], txn_id}
┌────────────────────────┐
│  Capability Broker     │  ← PCI 7.2.2  (intent → tool, least privilege)
└────────────────────────┘
    ↓ CapabilityRequest {tool_name, args, pci_scope}
┌────────────────────────┐
│   Policy Engine        │  ← PCI 7.3.2  (RBAC, HITL, justification)
└────────────────────────┘
    ↓ Authorised execution
┌────────────────────────┐
│    MCP Gateway         │  ← PCI 10.2.1 (single exec point + DataClassifier)
└────────────────────────┘
    ↓ ClassifiedValue {value, classification: PCI_CHD | SECRET | ...}
┌────────────────────────┐
│  Response Generator   │  ← PCI 3.4.1  (LLM, DLP validated output)
└────────────────────────┘
    ↓ Safe, masked response
""", language="text")
        st.divider()

        st.markdown("### PCI DSS v4.0.1 Control Mapping")
        pci_map = pe.get_pci_mapping()
        pci_rows = []
        for component, controls in pci_map.items():
            pci_rows.append({
                "Component":        component.replace("_", " ").title(),
                "PCI DSS v4.0.1 Controls": "  |  ".join(controls),
            })
        st.dataframe(pd.DataFrame(pci_rows), use_container_width=True, hide_index=True)
        st.divider()
    else:
        st.markdown("### Architecture (Vulnerable Mode)")
        st.code("""
User Input
    ↓
┌────────────────────────┐
│    LLM Agent            │  (no policy controls, no isolation)
└────────────────────────┘
    ↓ Direct tool calls
┌────────────────────────┐
│    MCP Tools            │  (cdv_detokenize, webhook_post)
└────────────────────────┘
    ↓ Raw unmasked response
""", language="text")
        st.divider()

    st.markdown("### Security Configurations")

    st.markdown("#### 0. Metrics & KPIs")
    metrics_rows = [
        {"Metric": "Blocked by PDP Risk Engine", "Value": kpis.get("blocked_by_risk_engine", 0)},
        {"Metric": "Isolated by PDP Risk Engine", "Value": kpis.get("isolated_by_risk_engine", 0)},
        {"Metric": "Prompt Injection Detections", "Value": kpis["prompt_injection_attempts"]},
        {"Metric": "Blocked Tool Calls (RBAC)", "Value": kpis["blocked_tool_calls"]},
        {"Metric": "Successful HITL Approvals", "Value": kpis["successful_hitl_approvals"]},
        {"Metric": "PAN Masking Events (DLP)", "Value": kpis["pan_masking_events"]},
        {"Metric": "Secret Masking Events (DLP)", "Value": kpis["secret_masking_events"]},
    ]
    st.dataframe(pd.DataFrame(metrics_rows), use_container_width=True, hide_index=True)
    st.divider()

    st.markdown("#### 1. Capability Registry (`capability_registry.yaml`)")
    st.code(yaml.dump(pe.registry), language="yaml")

    st.markdown("#### 2. Policy Specification (`policy.yaml`)")
    st.code(yaml.dump(pe.policy), language="yaml")

# ═══════════════════════════════════════════════
#  TAB 5 — AUDIT TRAIL
# ═══════════════════════════════════════════════
with tab_logs:
    st.markdown("### Audit Trail")
    logs = st.session_state.policy_engine.get_audit_logs()
    if not logs:
        st.info("No compliance audit records generated yet.", )
    else:
        formatted = [{"Timestamp": l["timestamp"], "Event": l["event_type"].upper(), "Status": l["status"].upper(), "Details": str(l["details"])} for l in reversed(logs)]
        df_logs = pd.DataFrame(formatted)
        _status_colors = {
            "WARNING": "#fca5a5",
            "FAILED": "#fca5a5",
            "BLOCKED": "#fca5a5",
            "PASS": "#86efac",
            "SUCCESS": "#86efac",
            "APPROVED": "#86efac",
            "MASKED": "#a5f3fc",
            "PENDING_APPROVAL": "#fde047",
            "ALLOW": "#86efac",
            "ALLOW_WITH_ISOLATION": "#fde047"
        }
        st.dataframe(df_logs.style.map(lambda val: f"color: {_status_colors.get(val, 'white')}", subset=["Status"]), use_container_width=True)
